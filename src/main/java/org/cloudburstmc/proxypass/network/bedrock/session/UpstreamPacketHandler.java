package org.cloudburstmc.proxypass.network.bedrock.session;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.cloudburstmc.protocol.bedrock.data.EncodingSettings;
import org.cloudburstmc.protocol.bedrock.data.PacketCompressionAlgorithm;
import org.cloudburstmc.protocol.bedrock.packet.*;
import org.cloudburstmc.protocol.bedrock.util.ChainValidationResult;
import org.cloudburstmc.protocol.bedrock.util.EncryptionUtils;
import org.cloudburstmc.protocol.bedrock.util.JsonUtils;
import org.cloudburstmc.protocol.common.PacketSignal;
import org.cloudburstmc.proxypass.ProxyPass;
import org.cloudburstmc.proxypass.network.bedrock.util.ForgeryUtils;
import org.cloudburstmc.proxypass.network.bedrock.util.SkinUtils;
import org.jose4j.json.JsonUtil;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class UpstreamPacketHandler implements BedrockPacketHandler {

    private final ProxyServerSession session;
    private final ProxyPass proxy;
    private JSONObject skinData;
    private JSONObject extraData;
    private List<String> chainData;
    private AuthData authData;
    private ProxyPlayerSession player;

    private static boolean verifyJwt(String jwt, PublicKey key) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setKey(key);
        jws.setCompactSerialization(jwt);
        return jws.verifySignature();
    }

    @Override
    public PacketSignal handle(RequestNetworkSettingsPacket packet) {
        int protocolVersion = packet.getProtocolVersion();

        if (protocolVersion != ProxyPass.PROTOCOL_VERSION) {
            PlayStatusPacket status = new PlayStatusPacket();
            if (protocolVersion > ProxyPass.PROTOCOL_VERSION) {
                status.setStatus(PlayStatusPacket.Status.LOGIN_FAILED_SERVER_OLD);
            } else {
                status.setStatus(PlayStatusPacket.Status.LOGIN_FAILED_CLIENT_OLD);
            }

            session.sendPacketImmediately(status);
            return PacketSignal.HANDLED;
        }
        session.setCodec(ProxyPass.CODEC);

        NetworkSettingsPacket networkSettingsPacket = new NetworkSettingsPacket();
        networkSettingsPacket.setCompressionThreshold(0);
        networkSettingsPacket.setCompressionAlgorithm(PacketCompressionAlgorithm.ZLIB);

        session.sendPacketImmediately(networkSettingsPacket);
        session.setCompression(PacketCompressionAlgorithm.ZLIB);
        return PacketSignal.HANDLED;
    }

    @Override
    public PacketSignal handle(LoginPacket packet) {
        try {
            // Manually extract raw JWT chain from the clientJwt JSON
            this.chainData = extractChainJwt(packet.getClientJwt());

            // Validate the chain to extract identity
            ChainValidationResult chain = EncryptionUtils.validateChain(this.chainData);
            JsonNode payload = ProxyPass.JSON_MAPPER.valueToTree(chain.rawIdentityClaims());

            if (payload.get("extraData").getNodeType() != JsonNodeType.OBJECT) {
                throw new RuntimeException("AuthData was not found!");
            }

            this.extraData = new JSONObject(JsonUtils.childAsType(chain.rawIdentityClaims(), "extraData", Map.class));

            this.authData = new AuthData(
                chain.identityClaims().extraData.displayName,
                chain.identityClaims().extraData.identity,
                chain.identityClaims().extraData.xuid
            );

            if (payload.get("identityPublicKey").getNodeType() != JsonNodeType.STRING) {
                throw new RuntimeException("Identity Public Key was not found!");
            }

            ECPublicKey identityPublicKey = EncryptionUtils.parseKey(payload.get("identityPublicKey").textValue());

            String clientJwt = packet.getClientJwt();
            verifyJwt(clientJwt, identityPublicKey);

            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(clientJwt);
            this.skinData = new JSONObject(JsonUtil.parseJson(jws.getUnverifiedPayload()));

            initializeProxySession();
        } catch (Exception e) {
            session.disconnect("disconnectionScreen.internalError.cantConnect");
            throw new RuntimeException("Unable to complete login", e);
        }
        return PacketSignal.HANDLED;
    }

    private void initializeProxySession() {
        log.debug("Initializing proxy session");

        this.proxy.newClient(this.proxy.getTargetAddress(), downstream -> {
            downstream.setCodec(ProxyPass.CODEC);
            downstream.setSendSession(this.session);
            downstream.getPeer().getCodecHelper().setEncodingSettings(EncodingSettings.CLIENT);
            this.session.setSendSession(downstream);

            ProxyPlayerSession proxySession = new ProxyPlayerSession(this.session, downstream, this.proxy, this.authData);
            this.player = proxySession;

            downstream.setPlayer(proxySession);
            this.session.setPlayer(proxySession);

            try {
                String jwt = chainData.get(chainData.size() - 1);
                JsonWebSignature jws = new JsonWebSignature();
                jws.setCompactSerialization(jwt);
                player.getLogger().saveJson("chainData", new JSONObject(JsonUtil.parseJson(jws.getUnverifiedPayload())));
                player.getLogger().saveJson("skinData", this.skinData);
                SkinUtils.saveSkin(proxySession, this.skinData);
            } catch (Exception e) {
                log.error("JSON output error: " + e.getMessage(), e);
            }

            String authData = ForgeryUtils.forgeAuthData(proxySession.getProxyKeyPair(), extraData);
            String skinData = ForgeryUtils.forgeSkinData(proxySession.getProxyKeyPair(), this.skinData);
            chainData.remove(chainData.size() - 1);
            chainData.add(authData);

            // Forge the clientJwt to include chain JSON in raw format
            String forgedChainJson;
            try {
                forgedChainJson = ProxyPass.JSON_MAPPER.writeValueAsString(chainData);
            } catch (Exception e) {
                throw new RuntimeException("Failed to write forged chain as JSON", e);
            }

            LoginPacket login = new LoginPacket();
            login.setProtocolVersion(ProxyPass.PROTOCOL_VERSION);
            login.setClientJwt("{\"chain\":" + forgedChainJson + "}");

            downstream.setPacketHandler(new DownstreamInitialPacketHandler(downstream, proxySession, this.proxy, login));
            downstream.setLogging(true);

            RequestNetworkSettingsPacket packet = new RequestNetworkSettingsPacket();
            packet.setProtocolVersion(ProxyPass.PROTOCOL_VERSION);
            downstream.sendPacketImmediately(packet);
        });
    }

    @Override
    public void onDisconnect(String reason) {
        if (this.session.getSendSession().isConnected()) {
            this.session.getSendSession().disconnect(reason);
        }
    }

    /**
     * Extracts the raw JWT chain from the clientJwt string that wraps it in a JSON object.
     */
    private List<String> extractChainJwt(String clientJwtJson) {
        try {
            JsonNode root = ProxyPass.JSON_MAPPER.readTree(clientJwtJson);
            JsonNode chainNode = root.get("chain");
            if (chainNode == null || !chainNode.isArray()) {
                throw new IllegalArgumentException("Missing or malformed 'chain' field in clientJwt");
            }
            return ProxyPass.JSON_MAPPER.convertValue(
                chainNode,
                ProxyPass.JSON_MAPPER.getTypeFactory().constructCollectionType(List.class, String.class)
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract chain JWT array from clientJwt JSON", e);
        }
    }
}
