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
    // 定义 SM9 加密主密钥结构体、加密主密钥的公共部分结构体、加密密钥结构体
    SM9_ENC_MASTER_KEY enc_master;
    SM9_ENC_MASTER_KEY enc_master_public;
    SM9_ENC_KEY enc_key;
    // 定义 SM9 签名主密钥结构体、签名主密钥的公共部分结构体、签名密钥结构体、签名上下文结构体
    SM9_SIGN_MASTER_KEY sign_master;
    SM9_SIGN_MASTER_KEY sign_master_public;
    SM9_SIGN_KEY sign_key;
    SM9_SIGN_CTX sign_ctx;
    // 用户标识
    const char *id = "Alice";
    // 缓冲区和指针用于 DER 编码和解码
    uint8_t buf[512];
    uint8_t *p = buf;
    const uint8_t *cp = buf;
    // 存储长度的变量
    size_t len;
    // 存储解密结果的缓冲区和长度
    char mbuf[256];
    size_t mlen;
    // 存储签名和签名长度的变量
    uint8_t sig[SM9_SIGNATURE_SIZE];
    size_t siglen;
    // 存储函数返回值
    int ret;

    // 生成 SM9 加密主密钥
    sm9_enc_master_key_generate(&enc_master);
    // 从主密钥中提取特定 ID 对应的加密密钥
    sm9_enc_master_key_extract_key(&enc_master, id, strlen(id), &enc_key);

    // 将加密主密钥的公共部分编码为 DER 格式，结果存储在 buf 中，len 存储编码后的长度
    sm9_enc_master_public_key_to_der(&enc_master, &p, &len);
    // 从 DER 格式解码加密主密钥的公共部分，结果存储在 enc_master_public 中，cp 指向 DER 编码的数据
    sm9_enc_master_public_key_from_der(&enc_master_public, &cp, &len);

    // 获取用户输入的明文
    char plaintext[256];
    printf("请输入明文: ");
    if (fgets(plaintext, sizeof(plaintext), stdin) == NULL) {
        fprintf(stderr, "无法读取输入\n");
        return 1;
    }
    // 去除换行符
    size_t plaintext_len = strlen(plaintext);
    if (plaintext_len > 0 && plaintext[plaintext_len - 1] == '\n') {
        plaintext[plaintext_len - 1] = '\0';
    }

    // 使用加密主密钥的公共部分对明文进行加密，结果存储在 buf 中，len 存储密文长度
    sm9_encrypt(&enc_master_public, id, strlen(id), (uint8_t *)plaintext, strlen(plaintext), buf, &len);

    // 使用加密密钥对密文进行解密，结果存储在 mbuf 中，mlen 存储解密后的明文长度
    ret = sm9_decrypt(&enc_key, id, strlen(id), buf, len, (uint8_t *)mbuf, &mlen);
    if (ret != 1) {
        fprintf(stderr, "解密失败\n");
        return 1;
    }
    mbuf[mlen] = 0;
    printf("解密结果: %s\n", mbuf);

    // 生成 SM9 签名主密钥
    sm9_sign_master_key_generate(&sign_master);
    // 从主密钥中提取特定 ID 对应的签名密钥
    sm9_sign_master_key_extract_key(&sign_master, id, strlen(id), &sign_key);

    // 初始化签名上下文
    sm9_sign_init(&sign_ctx);
    // 更新签名上下文的消息
    sm9_sign_update(&sign_ctx, (uint8_t *)"hello world", strlen("hello world"));
    // 结束签名过程，得到签名和签名长度
    sm9_sign_finish(&sign_ctx, &sign_key, sig, &siglen);

    // 在标准输出流上格式化输出签名
    format_bytes(stdout, 0, 0, "signature", sig, siglen);

    // 将签名主密钥的公共部分编码为 DER 格式，结果存储在 buf 中，len 存储编码后的长度
    sm9_sign_master_public_key_to_der(&sign_master, &p, &len);
    // 从 DER 格式解码签名主密钥的公共部分，结果存储在 sign_master_public 中，cp 指向 DER 编码的数据
    sm9_sign_master_public_key_from_der(&sign_master_public, &cp, &len);

    // 初始化签名验证上下文
    sm9_verify_init(&sign_ctx);
    // 更新签名验证上下文的消息
    sm9_verify_update(&sign_ctx, (uint8_t *)"hello world", strlen("hello world"));
    // 验证签名
    ret = sm9_verify_finish(&sign_ctx, sig, siglen, &sign_master_public, id, strlen(id));
    printf("验证 %s\n", ret == 1 ? "成功" : "失败");

    return 0;
}
