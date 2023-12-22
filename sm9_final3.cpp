//
// Created by mouzi on 2023/12/20.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>

int main(void)
{
    // 用户标识
    const char *id = "Alice";

    // 加密相关参数
    SM9_ENC_MASTER_KEY enc_master;
    SM9_ENC_MASTER_KEY enc_master_public;
    SM9_ENC_KEY enc_key;
    uint8_t enc_buf[512];
    uint8_t *enc_p = enc_buf;
    const uint8_t *enc_cp = enc_buf;
    size_t enc_len;
    char mbuf[256];
    char password[256];
    char sign_message[256];
    char verify_message[256];
    size_t mlen;
    int enc_ret;

    // 签名相关参数
    SM9_SIGN_MASTER_KEY sign_master;
    SM9_SIGN_MASTER_KEY sign_master_public;
    SM9_SIGN_KEY sign_key;
    SM9_SIGN_CTX sign_ctx;
    uint8_t sig[SM9_SIGNATURE_SIZE];
    size_t siglen;
    uint8_t sign_buf[512];
    uint8_t *sign_p = sign_buf;
    const uint8_t *sign_cp = sign_buf;
    size_t sign_len;
    int sign_ret;

    // 生成 SM9 加密主密钥
    sm9_enc_master_key_generate(&enc_master);
    sm9_enc_master_key_extract_key(&enc_master, id, strlen(id), &enc_key);
    sm9_enc_master_public_key_to_der(&enc_master, &enc_p, &enc_len);
    sm9_enc_master_public_key_from_der(&enc_master_public, &enc_cp, &enc_len);

    char plaintext[256];
    printf("请输入明文: ");
    if (fgets(plaintext, sizeof(plaintext), stdin) == NULL) {
        fprintf(stderr, "无法读取输入\n");
        return 1;
    }
    size_t plaintext_len = strlen(plaintext);
    if (plaintext_len > 0 && plaintext[plaintext_len - 1] == '\n') {
        plaintext[plaintext_len - 1] = '\0';
    }



    sm9_encrypt(&enc_master_public, id, strlen(id), (uint8_t *)plaintext, strlen(plaintext), enc_buf, &enc_len);

    enc_ret = sm9_decrypt(&enc_key, id, strlen(id), enc_buf, enc_len, (uint8_t *)mbuf, &mlen);
    if (enc_ret != 1) {
        fprintf(stderr, "解密失败\n");
        return 1;
    }
    mbuf[mlen] = 0;
    printf("解密结果: %s\n", mbuf);

    printf("请输入要签名的消息:");
    if(fgets(sign_message,sizeof(sign_message),stdin) == NULL) {
        fprintf(stderr,"无法读取输入");
        return 1;
    }

    sm9_sign_master_key_generate(&sign_master);
    sm9_sign_master_key_extract_key(&sign_master, id, strlen(id), &sign_key);
    sm9_sign_init(&sign_ctx);
    sm9_sign_update(&sign_ctx, (uint8_t *)sign_message, strlen(sign_message));
    sm9_sign_finish(&sign_ctx, &sign_key, sig, &siglen);

    //输出签名
    printf("\n签名结果\n");
    format_bytes(stdout,0,0,"signature",sig,siglen);

    //验证签名
    printf("\n请输入要签名的消息: ");
    if(fgets(verify_message,sizeof(verify_message),stdin) == NULL) {
        fprintf(stderr,"无法读取输入\n");
        return 1;
    }

    sm9_sign_master_public_key_to_der(&sign_master, &sign_p, &sign_len);
    sm9_sign_master_public_key_from_der(&sign_master_public, &sign_cp, &sign_len);
    sm9_verify_init(&sign_ctx);
    sm9_verify_update(&sign_ctx, (uint8_t *)verify_message, strlen(verify_message));
    sign_ret = sm9_verify_finish(&sign_ctx, sig, siglen, &sign_master_public, id, strlen(id));

    printf("verify %s\n", sign_ret == 1 ? "成功" : "失败");
    printf("\nSM9加密主密钥信息:\n");
    sm9_enc_master_key_info_encrypt_to_pem(&enc_master, password, stdout);
    printf("\nSM9签名主密钥信息:\n");
    sm9_sign_master_key_info_encrypt_to_pem(&sign_master, password, stdout);

    return 0;
}
