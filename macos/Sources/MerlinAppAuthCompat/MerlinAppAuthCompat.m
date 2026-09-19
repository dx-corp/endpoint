#import "MerlinAppAuthCompat.h"
#import <macOS/OIDRedirectHTTPHandler.h>

NSURL * _Nullable MerlinStartLoopbackListener(OIDRedirectHTTPHandler *handler, uint16_t port) {
    NSError *error = nil;
    NSURL *url = [handler startHTTPListener:&error withPort:port];
    if (error != nil || url == nil) {
        [handler cancelHTTPListener];
        return nil;
    }
    return url;
}
