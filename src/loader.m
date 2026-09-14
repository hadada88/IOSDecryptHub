// loader.m — IOSDecryptHub 越狱注入加载器
//
// 由 rootless 环境的 ElleKit 加载到 UIKit App（Filter: com.apple.UIKit）。
// 唯一职责：读取偏好设置 → 判断当前 App 是否启用 → dlopen 主 dylib。
// 不包含任何 hook 逻辑。hook 全部由主 dylib 的 constructor 完成。
//
// rootless 路径：
//   /var/jb/usr/lib/IOSDecryptHub/decrypt_helper.dylib

#import <Foundation/Foundation.h>
#import "dh_shared.h"
#import <dlfcn.h>
#import <syslog.h>

#define LOADER_TAG      "[IOSDecryptHub]"
#define PREFS_DOMAIN    DH_DOMAIN_LOADER
#define PREFS_KEY       DH_KEY_BUNDLES
#define PREFS_PATH      DH_LEGACY_CONFIG_PATH
#define CONFIG_NAME     DH_CONFIG_REL

// rootless 下 /var/jb 只是引导期别名，宿主沙盒中不一定可见。优先从 loader 的 dyld
// 实际路径推导同一 bootstrap 下的主 dylib，再兼容固定路径。
static NSArray<NSString *> *dh_dylib_candidates(void) {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    Dl_info info = {0};
    if (dladdr((const void *)&dh_dylib_candidates, &info) != 0 && info.dli_fname) {
        NSString *loaderPath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *libDir = [[loaderPath stringByDeletingLastPathComponent]
            stringByDeletingLastPathComponent];
        if (libDir.length) {
            [paths addObject:[libDir stringByAppendingPathComponent:
                @"IOSDecryptHub/decrypt_helper.dylib"]];
        }
    }
    [paths addObject:@"/var/jb/usr/lib/IOSDecryptHub/decrypt_helper.dylib"];
    return paths;
}

static NSArray<NSString *> *dh_config_candidates(void) {
    NSMutableArray<NSString *> *paths = [NSMutableArray array];
    Dl_info info = {0};
    if (dladdr((const void *)&dh_config_candidates, &info) != 0 && info.dli_fname) {
        NSString *loaderPath = [NSString stringWithUTF8String:info.dli_fname];
        NSString *libDir = [[loaderPath stringByDeletingLastPathComponent]
            stringByDeletingLastPathComponent];
        if (libDir.length) {
            [paths addObject:[libDir stringByAppendingPathComponent:CONFIG_NAME]];
        }
    }
    [paths addObject:@"/var/jb/usr/lib/IOSDecryptHub/config/enabledBundles.plist"];
    return paths;
}

static NSArray *_Nullable dh_user_enabled_bundles(void) {
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];
    id enabled = prefs[PREFS_KEY];
    if ([enabled isKindOfClass:[NSArray class]]) return enabled;

    CFPreferencesAppSynchronize((__bridge CFStringRef)PREFS_DOMAIN);
    CFPropertyListRef value = CFPreferencesCopyAppValue(
        (__bridge CFStringRef)PREFS_KEY,
        (__bridge CFStringRef)PREFS_DOMAIN);
    if (value && CFGetTypeID(value) == CFArrayGetTypeID()) {
        return CFBridgingRelease(value);
    }
    if (value) CFRelease(value);
    return nil;
}

// 说明：曾短暂加过"我们自己的组件不注入"的特例（想让管理器 App 里不弹悬浮窗），
// 已撤销 —— 用户反馈里看到的悬浮窗真正原因是"开关被打开了"，不是产品行为异常。
// 开关语义保持处处一致：列在名单里的 App 就会被注入，没有例外。
// 相关：管理器 App 与设置面板同样出现在列表里，可以被显式打开（例如当服务宿主用）。

// 读取偏好：判断当前 bundleID 是否在启用列表中
static BOOL dh_should_inject(NSString *bundleID) {
    if (!bundleID || bundleID.length == 0) return NO;

    // 跳过系统关键进程（避免不必要的开销）
    if ([bundleID hasPrefix:@"com.apple."]) return NO;


    NSArray *enabled = dh_user_enabled_bundles();
    @try {
        // RootHide 下优先使用 mobile 可写的副本，避免旧的空配置遮蔽新名单。
        if ([enabled isKindOfClass:[NSArray class]]) {
            return [enabled containsObject:bundleID];
        }

        // 插件自带配置与主 dylib 位于同一越狱授权路径，不受宿主 App 偏好容器隔离。
        NSDictionary *prefs = nil;
        for (NSString *configPath in dh_config_candidates()) {
            prefs = [NSDictionary dictionaryWithContentsOfFile:configPath];
            enabled = prefs[PREFS_KEY];
            if ([enabled isKindOfClass:[NSArray class]]) break;
        }

        if (![enabled isKindOfClass:[NSArray class]]) {
            prefs = [[NSUserDefaults standardUserDefaults]
                persistentDomainForName:PREFS_DOMAIN];
            enabled = prefs[PREFS_KEY];
        }
    } @catch (__unused NSException *exception) {
        return NO;
    }
    if (!enabled || ![enabled isKindOfClass:[NSArray class]]) return NO;

    return [enabled containsObject:bundleID];
}

__attribute__((constructor))
static void dh_loader_init(void) {
    @autoreleasepool {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];

        // 默认不注入任何 App —— 只有用户在设置中明确开启的才注入
        if (!dh_should_inject(bundleID)) {
            return;
        }

        // 不先用 access() 探测：宿主沙盒可能拒绝路径查询，但 dyld 仍可加载由越狱
        // 注入框架授权的镜像。逐个 dlopen 才能得到真实结果。
        for (NSString *dylibPath in dh_dylib_candidates()) {
            syslog(LOG_INFO, LOADER_TAG " 注入 %s → %s",
                   bundleID.UTF8String, dylibPath.UTF8String);
            void *handle = dlopen(dylibPath.fileSystemRepresentation, RTLD_NOW);
            if (handle) return;
        }
        syslog(LOG_ERR, LOADER_TAG " 主 dylib 加载失败 (%s): %s",
               bundleID.UTF8String, dlerror() ?: "unknown error");
    }
}
