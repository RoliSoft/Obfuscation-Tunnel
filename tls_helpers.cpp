#pragma once
#include "shared.cpp"
#if HAVE_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static void print_cert_hash(X509* cert)
{
    unsigned char hash[160 / 8];
    unsigned int hash_size = sizeof(hash);
    if (X509_digest(cert, EVP_sha1(), hash, &hash_size) != 1) return;

    for (unsigned int i = 0; i < hash_size; i++)
    {
        if (i % 2 == 0 && i != 0) printf(":");
        printf("%02x", hash[i]);
    }
}

static int ssl_gen_cert(const char *cn, X509 **cert, EVP_PKEY **key)
{
    int res, ret = 0;

    RSA *rsa;
    *key = EVP_PKEY_new();
    do {
        BIGNUM *bne = BN_new();
        ret = BN_set_word(bne, RSA_F4);
        if (ret != 1) goto cleanup;

        rsa = RSA_new();
        ret = RSA_generate_key_ex(rsa, 2048, bne, NULL);
        if (ret != 1) goto cleanup;

        res = RSA_check_key(rsa);
    } while (res == 0);

    if (res == -1) return EXIT_FAILURE;
    if (EVP_PKEY_assign_RSA(*key, rsa) == 0)
    {
        RSA_free(rsa);
        goto cleanup;
    }

    *cert = X509_new();
    if (X509_set_version(*cert, 2) == 0) goto cleanup;
    if (X509_NAME_add_entry_by_txt(X509_get_subject_name(*cert), "commonName", MBSTRING_ASC, (unsigned char*)cn, -1, -1, 0) == 0) goto cleanup;

    ASN1_INTEGER_set(X509_get_serialNumber(*cert), rand() & 0x7FFFFFFF);

    char dnsName[128];
    res = snprintf(dnsName, sizeof(dnsName), "DNS:%s", cn);
    if (res < 0) goto cleanup;

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, *cert, *cert, NULL, NULL, 0);

    X509_EXTENSION *ext;
    ext = X509V3_EXT_conf(NULL, &ctx, "subjectAltName", dnsName);
    if (ext == NULL) goto cleanup;
    if (X509_add_ext(*cert, ext, -1) == 0) goto cleanup;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined LIBRESSL_VERSION_NUMBER
    {
        ASN1_TIME *tb = NULL, *ta = NULL;

        if (X509_set_issuer_name(*cert, X509_get_subject_name(*cert)) == 0
            || (tb = ASN1_STRING_dup(X509_get0_notBefore(*cert))) == 0
            || X509_gmtime_adj(tb, 0) == 0
            || X509_set1_notBefore(*cert, tb) == 0
            || (ta = ASN1_STRING_dup(X509_get0_notAfter(*cert))) == 0
            || X509_gmtime_adj(ta, 60) == 0
            || X509_set1_notAfter(*cert, ta) == 0
            || X509_set_pubkey(*cert, *key) == 0)
        {
            ASN1_STRING_free(tb);
            ASN1_STRING_free(ta);
            goto cleanup;
        }

        ASN1_STRING_free(tb);
        ASN1_STRING_free(ta);
    }
#else
    if (X509_set_issuer_name(*cert, X509_get_subject_name(*cert)) == 0
        || X509_gmtime_adj(X509_get_notBefore(*cert), 0) == 0
        || X509_gmtime_adj(X509_get_notAfter(*cert), 60 * 60 * 24 * 365) == 0
        || X509_set_pubkey(*cert, *key) == 0)
    {
        goto cleanup;
    }
#endif

    if (X509_sign(*cert, *key, EVP_sha1()) == 0) goto cleanup;
    return EXIT_SUCCESS;

cleanup:
    if (*cert != NULL) X509_free(*cert);
    if (*key != NULL) EVP_PKEY_free(*key);

    return EXIT_FAILURE;
}
#endif
