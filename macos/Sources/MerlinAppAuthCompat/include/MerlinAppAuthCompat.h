#import <Foundation/Foundation.h>
@class OIDRedirectHTTPHandler;

/// AppAuth 3.0.0 declares a nonnull result but returns nil on bind failure.
/// Preserve that nullable result across the Objective-C/Swift boundary.
FOUNDATION_EXPORT NSURL * _Nullable MerlinStartLoopbackListener(
    OIDRedirectHTTPHandler * _Nonnull handler, uint16_t port);
