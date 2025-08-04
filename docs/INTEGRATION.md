# Bitcoin/Lightning Network Integration Guide

This guide shows how to integrate libnostr-c with Bitcoin and Lightning Network applications.

## Overview

libnostr-c provides native support for Bitcoin-related functionality through:
- **NIP-57**: Lightning zaps for instant Bitcoin payments
- **Secp256k1**: Same cryptographic primitives as Bitcoin
- **Lightning invoices**: Direct integration with Lightning nodes
- **Bitcoin addresses**: Support for on-chain Bitcoin transactions

## Lightning Network Integration (NIP-57)

### Setting Up Zap Support

#### 1. LNURL Server Configuration

Configure your Lightning node to support zaps:

```json
{
  "allowsNostr": true,
  "nostrPubkey": "your_server_nostr_pubkey_hex",
  "callback": "https://your-ln-node.com/lnurl/pay/callback",
  "minSendable": 1000,
  "maxSendable": 10000000,
  "metadata": "[[\"text/plain\",\"Lightning tips\"]]"
}
```

#### 2. Basic Zap Implementation

```c
#include <nostr.h>

typedef struct {
    char* lnurl;
    char* callback_url;
    char* nostr_pubkey;
    uint64_t min_sendable;
    uint64_t max_sendable;
} lnurl_info_t;

int send_zap(const char* recipient_npub, uint64_t amount_msats, const char* message) {
    // Initialize library
    if (nostr_init() != NOSTR_OK) {
        return -1;
    }
    
    // Parse recipient public key
    nostr_key recipient;
    if (nostr_key_from_bech32(recipient_npub, &recipient) != NOSTR_OK) {
        nostr_cleanup();
        return -1;
    }
    
    // Fetch LNURL info (implement your HTTP client)
    lnurl_info_t lnurl_info;
    if (fetch_lnurl_info(recipient_npub, &lnurl_info) != 0) {
        nostr_cleanup();
        return -1;
    }
    
    // Validate amount
    if (amount_msats < lnurl_info.min_sendable || 
        amount_msats > lnurl_info.max_sendable) {
        printf("Amount out of range: %lu-%lu msats\n", 
               lnurl_info.min_sendable, lnurl_info.max_sendable);
        free_lnurl_info(&lnurl_info);
        nostr_cleanup();
        return -1;
    }
    
    // Create zap request
    const char* relays[] = {
        "wss://relay.damus.io",
        "wss://nostr.band"
    };
    
    nostr_event* zap_request;
    if (nostr_zap_create_request(&zap_request, amount_msats, &recipient, 
                                lnurl_info.lnurl, message, relays, 2) != NOSTR_OK) {
        free_lnurl_info(&lnurl_info);
        nostr_cleanup();
        return -1;
    }
    
    // Sign with sender's key
    nostr_privkey sender_privkey;
    nostr_key sender_pubkey;
    load_sender_keys(&sender_privkey, &sender_pubkey);  // Implement key loading
    
    if (nostr_event_sign(zap_request, &sender_privkey) != NOSTR_OK) {
        nostr_event_destroy(zap_request);
        free_lnurl_info(&lnurl_info);
        nostr_cleanup();
        return -1;
    }
    
    // Send to LNURL callback and get invoice
    char* invoice = send_zap_request(zap_request, &lnurl_info);
    if (!invoice) {
        nostr_event_destroy(zap_request);
        free_lnurl_info(&lnurl_info);
        nostr_cleanup();
        return -1;
    }
    
    // Pay the invoice (integrate with your Lightning client)
    int payment_result = pay_lightning_invoice(invoice);
    
    // Clean up
    free(invoice);
    nostr_event_destroy(zap_request);
    free_lnurl_info(&lnurl_info);
    nostr_cleanup();
    
    return payment_result;
}
```

#### 3. Zap Receipt Verification

```c
int verify_zap_receipt(const char* receipt_json, const char* expected_amount) {
    nostr_event* receipt;
    if (nostr_event_from_json(receipt_json, &receipt) != NOSTR_OK) {
        return -1;
    }
    
    // Extract zap information
    uint64_t amount = 0;
    char* bolt11 = NULL;
    char preimage[65] = {0};
    nostr_event* original_request = NULL;
    
    if (nostr_zap_parse_receipt(receipt, &amount, &bolt11, preimage, &original_request) != NOSTR_OK) {
        nostr_event_destroy(receipt);
        return -1;
    }
    
    printf("Zap verified!\n");
    printf("Amount: %lu msats\n", amount);
    printf("Invoice: %.50s...\n", bolt11);
    printf("Preimage: %s\n", preimage);
    
    // Clean up
    free(bolt11);
    nostr_event_destroy(original_request);
    nostr_event_destroy(receipt);
    
    return 0;
}
```

### Lightning Node Integration

#### Core Lightning (CLN) Integration

```c
// Example integration with Core Lightning's JSON-RPC
#include <cjson/cJSON.h>

typedef struct {
    char* bolt11;
    char* payment_hash;
    char* preimage;
    uint64_t amount_msat;
} lightning_payment_t;

int pay_lightning_invoice(const char* bolt11) {
    // Prepare CLN pay command
    cJSON* request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "method", "pay");
    
    cJSON* params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "bolt11", bolt11);
    cJSON_AddItemToObject(request, "params", params);
    
    char* request_str = cJSON_Print(request);
    
    // Send to CLN via Unix socket or HTTP
    char* response_str = send_cln_request(request_str);
    
    cJSON* response = cJSON_Parse(response_str);
    cJSON* result = cJSON_GetObjectItem(response, "result");
    
    int success = 0;
    if (result) {
        cJSON* status = cJSON_GetObjectItem(result, "status");
        if (status && strcmp(cJSON_GetStringValue(status), "complete") == 0) {
            success = 1;
            
            // Extract preimage for verification
            cJSON* preimage_json = cJSON_GetObjectItem(result, "payment_preimage");
            if (preimage_json) {
                printf("Payment successful! Preimage: %s\n", 
                       cJSON_GetStringValue(preimage_json));
            }
        }
    }
    
    // Clean up
    free(request_str);
    free(response_str);
    cJSON_Delete(request);
    cJSON_Delete(response);
    
    return success ? 0 : -1;
}
```

#### LND Integration

```c
// Example integration with LND's gRPC API
#include <grpc/grpc.h>

int pay_lnd_invoice(const char* bolt11) {
    // Initialize gRPC channel to LND
    grpc_channel* channel = grpc_insecure_channel_create("localhost:10009", NULL, NULL);
    
    // Create payment request
    // Note: This is pseudocode - actual LND integration requires 
    // generated protobuf bindings
    
    lnrpc_SendRequest request = LNRPC_SEND_REQUEST__INIT;
    request.payment_request = (char*)bolt11;
    
    // Send payment
    lnrpc_SendResponse* response = NULL;
    grpc_status_code status = lightning_send_payment_sync(channel, &request, &response);
    
    int success = 0;
    if (status == GRPC_STATUS_OK && response) {
        if (response->payment_error == NULL || strlen(response->payment_error) == 0) {
            success = 1;
            printf("LND payment successful! Hash: %s\n", response->payment_hash);
        } else {
            printf("LND payment failed: %s\n", response->payment_error);
        }
    }
    
    // Clean up
    if (response) {
        lnrpc_send_response__free_unpacked(response, NULL);
    }
    grpc_channel_destroy(channel);
    
    return success ? 0 : -1;
}
```

## Bitcoin On-Chain Integration

### Address Generation

```c
#include <nostr.h>
#include <secp256k1.h>

// Generate Bitcoin address from Nostr key
int nostr_key_to_bitcoin_address(const nostr_privkey* nostr_privkey, char* address, size_t address_size) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    
    // Create Bitcoin public key from Nostr private key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, nostr_privkey->data)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    
    // Serialize to compressed format
    size_t pubkey_len = 33;
    unsigned char pubkey_compressed[33];
    secp256k1_ec_pubkey_serialize(ctx, pubkey_compressed, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);
    
    // Generate P2WPKH address (implement Bitcoin address encoding)
    if (pubkey_to_p2wpkh_address(pubkey_compressed, address, address_size) != 0) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    
    secp256k1_context_destroy(ctx);
    return 0;
}
```

### Transaction Signing

```c
// Sign Bitcoin transaction with Nostr private key
int sign_bitcoin_transaction(const nostr_privkey* privkey, 
                           const unsigned char* tx_hash, 
                           unsigned char* signature) {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(ctx, &sig, tx_hash, privkey->data, NULL, NULL)) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    
    // Serialize signature in DER format
    size_t siglen = 72;
    secp256k1_ecdsa_signature_serialize_der(ctx, signature, &siglen, &sig);
    
    secp256k1_context_destroy(ctx);
    return (int)siglen;
}
```

## Complete Zap Application Example

### Zap Server Implementation

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nostr.h>
#include <microhttpd.h>

typedef struct {
    nostr_privkey server_privkey;
    nostr_key server_pubkey;
    char* lightning_node_url;
    char* callback_url;
} zap_server_t;

// LNURL-pay endpoint
enum MHD_Result handle_lnurl_pay(void* cls, struct MHD_Connection* connection,
                                const char* url, const char* method,
                                const char* version, const char* upload_data,
                                size_t* upload_data_size, void** con_cls) {
    zap_server_t* server = (zap_server_t*)cls;
    
    if (strcmp(method, "GET") == 0) {
        // Return LNURL-pay info
        cJSON* response = cJSON_CreateObject();
        cJSON_AddStringToObject(response, "callback", server->callback_url);
        cJSON_AddNumberToObject(response, "minSendable", 1000);
        cJSON_AddNumberToObject(response, "maxSendable", 10000000);
        cJSON_AddTrueToObject(response, "allowsNostr");
        
        char pubkey_hex[65];
        nostr_key_to_hex(&server->server_pubkey, pubkey_hex, sizeof(pubkey_hex));
        cJSON_AddStringToObject(response, "nostrPubkey", pubkey_hex);
        
        char* response_str = cJSON_Print(response);
        
        struct MHD_Response* mhd_response = 
            MHD_create_response_from_buffer(strlen(response_str), response_str, MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(mhd_response, "Content-Type", "application/json");
        
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
        MHD_destroy_response(mhd_response);
        cJSON_Delete(response);
        
        return ret;
    }
    
    return MHD_NO;
}

// Zap callback endpoint
enum MHD_Result handle_zap_callback(void* cls, struct MHD_Connection* connection,
                                   const char* url, const char* method,
                                   const char* version, const char* upload_data,
                                   size_t* upload_data_size, void** con_cls) {
    zap_server_t* server = (zap_server_t*)cls;
    
    if (strcmp(method, "GET") == 0) {
        // Parse query parameters
        const char* amount_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "amount");
        const char* nostr_param = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "nostr");
        
        if (!amount_str || !nostr_param) {
            return MHD_NO;
        }
        
        uint64_t amount = strtoull(amount_str, NULL, 10);
        
        // Validate zap request
        nostr_event* zap_request;
        if (nostr_event_from_json(nostr_param, &zap_request) != NOSTR_OK) {
            return MHD_NO;
        }
        
        // Generate Lightning invoice
        char* invoice = generate_lightning_invoice(server->lightning_node_url, amount, nostr_param);
        if (!invoice) {
            nostr_event_destroy(zap_request);
            return MHD_NO;
        }
        
        // Return invoice
        cJSON* response = cJSON_CreateObject();
        cJSON_AddStringToObject(response, "pr", invoice);
        
        char* response_str = cJSON_Print(response);
        
        struct MHD_Response* mhd_response = 
            MHD_create_response_from_buffer(strlen(response_str), response_str, MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(mhd_response, "Content-Type", "application/json");
        
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, mhd_response);
        
        // Clean up
        MHD_destroy_response(mhd_response);
        cJSON_Delete(response);
        free(invoice);
        nostr_event_destroy(zap_request);
        
        return ret;
    }
    
    return MHD_NO;
}

int main() {
    zap_server_t server;
    
    // Initialize server
    if (nostr_init() != NOSTR_OK) {
        return 1;
    }
    
    // Generate server keypair (in production, load from secure storage)
    nostr_key_generate(&server.server_privkey, &server.server_pubkey);
    
    server.lightning_node_url = "http://localhost:8080";  // Your Lightning node
    server.callback_url = "https://your-domain.com/zap/callback";
    
    // Start HTTP server
    struct MHD_Daemon* daemon = MHD_start_daemon(
        MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD,
        8080,
        NULL, NULL,
        handle_lnurl_pay,
        &server,
        MHD_OPTION_END
    );
    
    if (!daemon) {
        nostr_cleanup();
        return 1;
    }
    
    printf("Zap server running on port 8080\n");
    printf("LNURL endpoint: http://localhost:8080/.well-known/lnurlp/zap\n");
    
    // Keep server running
    getchar();
    
    MHD_stop_daemon(daemon);
    nostr_cleanup();
    return 0;
}
```

## Best Practices

### Security Considerations

1. **Key Management**:
   - Store private keys securely (hardware wallets, encrypted storage)
   - Never log or transmit private keys in plaintext
   - Use proper random number generation

2. **Lightning Integration**:
   - Validate all zap requests before creating invoices
   - Implement proper authentication for your Lightning node
   - Set reasonable amount limits

3. **Network Security**:
   - Use TLS for all HTTP endpoints
   - Validate all input data
   - Implement rate limiting

### Performance Optimization

1. **Connection Pooling**:
   - Maintain persistent connections to frequently used relays
   - Implement connection failover

2. **Caching**:
   - Cache LNURL responses
   - Cache relay metadata

3. **Async Operations**:
   - Use callbacks for non-blocking operations
   - Implement proper event loops

### Error Handling

```c
// Robust error handling pattern
int robust_zap_operation(const char* recipient, uint64_t amount) {
    int result = -1;
    nostr_event* event = NULL;
    char* invoice = NULL;
    
    if (nostr_init() != NOSTR_OK) {
        goto cleanup;
    }
    
    // Operation logic here...
    
    result = 0;  // Success
    
cleanup:
    if (event) nostr_event_destroy(event);
    if (invoice) free(invoice);
    nostr_cleanup();
    
    return result;
}
```

## Integration Checklist

- [ ] LNURL server configured with `allowsNostr: true`
- [ ] Server Nostr keypair generated and configured
- [ ] Lightning node accessible and authenticated
- [ ] Zap request validation implemented
- [ ] Invoice generation integrated
- [ ] Zap receipt generation implemented
- [ ] Error handling and logging in place
- [ ] Rate limiting configured
- [ ] TLS/HTTPS enabled
- [ ] Key storage secured

## Resources

- [NIP-57 Specification](https://github.com/nostr-protocol/nips/blob/master/57.md)
- [LNURL Specification](https://github.com/lnurl/luds)
- [libsecp256k1 Documentation](https://github.com/bitcoin-core/secp256k1)
