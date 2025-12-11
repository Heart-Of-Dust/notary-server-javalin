package com.notary.service;

import com.notary.exception.NotaryException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import java.security.MessageDigest;
import java.nio.ByteBuffer;
import java.util.Base64;

public class TsaValidationService {


    public long validateToken(String tsaTokenBase64, String userId,
                              String msgHash, long clientTsMs) {
        try {
            byte[] tokenBytes = Base64.getDecoder().decode(tsaTokenBase64);
            TimeStampToken tsToken = new TimeStampToken(new CMSSignedData(tokenBytes));

            /* ---------- 正确验证签名 ---------- */
            SignerInformation signerInfo = tsToken.toSignerInformation();
            JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder();
            SignerInformationVerifier verifier = builder.build(tsaCert);
            signerInfo.verify(verifier);

            TimeStampTokenInfo info = tsToken.getTimeStampInfo();
            byte[] tokenImprint = info.getMessageImprintDigest();
            long tsaTime = info.getGenTime().getTime();

            byte[] expectedImprint = calculateImprint(userId, msgHash, clientTsMs);
            if (!MessageDigest.isEqual(tokenImprint, expectedImprint)) {
                throw new NotaryException("TSA imprint mismatch", 409);
            }
            return tsaTime;

        } catch (NotaryException e) {
            throw e;
        } catch (Exception e) {
            throw new NotaryException("TSA validation failed: " + e.getMessage(), 409);
        }
    }


    private byte[] calculateImprint(String userId, String msgHash, long clientTsMs) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // 1. UTF-8 UserID
            digest.update(userId.getBytes("UTF-8"));

            // 2. Hex decode MsgHash
            digest.update(hexStringToByteArray(msgHash));

            // 3. BigEndian 64-bit timestamp
            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.putLong(clientTsMs);
            digest.update(buffer.array());

            return digest.digest();
        } catch (Exception e) {
            throw new RuntimeException("Imprint calculation failed", e);
        }
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}