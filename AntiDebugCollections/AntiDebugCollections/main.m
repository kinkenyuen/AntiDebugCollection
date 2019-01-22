//
//  main.m
//  AntiDebugCollections
//
//  Created by kinken on 2019/1/21.
//  Copyright © 2019 kinkenyuen. All rights reserved.
//

#ifdef DEBUG
#else
#define NSLog(...) {};
#endif

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

//ptrace反调试
#import <dlfcn.h>

//sysctl反调试
#include <stdio.h>
#include <sys/types.h>
//#include <unistd.h>
#include <sys/sysctl.h>
#include <stdlib.h>

//task_get_exception_ports反调试
#include <mach/task.h>
#include <mach/mach_init.h>

//ioctl反调试
#include <termios.h>
#include <sys/ioctl.h>

/*ptrace反调试*/
typedef int (*ptrace_ptr_t)(int request, pid_t pid, caddr_t addr, int data);

#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif

void disable_debug_ptrace() {
    /**
     Mac OSX可以直接调用ptrace(PT_DENY_ATTACH, 0, 0, 0)
     但是不能直接在iOS中调用，因此用dlopen与dlsym打开
     */
    void *handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}

/*sysctl反调试*/
static bool disable_debug_sysctl(void) {
    /**
     返回ture如果当前进程被调试（包括在调试器下运行以及有调试器附加）
     */
    int mib[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    
    //初始化flag，如果sysctl因一些奇怪的原因查询失败，用这个预设值
    info.kp_proc.p_flag = 0;
    
    //初始化mib数组，用来告诉sysctl我们需要查询的进程信息
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    
    if (sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &info_size, NULL, 0) == -1) {
        perror("perror sysctl");
        exit(-1);
    }
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

int main(int argc, char * argv[]) {
    #ifdef DEBUG
    #else
        disable_debug_ptrace();
    #endif
    NSLog(@"Bypassed ptrace反调试！");
    
    if (disable_debug_sysctl()) {
        exit(-1);
    }else {
        NSLog(@"Bypassed sysctl反调试!");
    }
    
    //另一种方式调用ptrace
    syscall(26, 31, 0, 0);
    NSLog(@"Bypassed syscall()");
    
    /*检测异常端口*/
    struct ios_execp_info {
        exception_mask_t masks[EXC_TYPES_COUNT];
        mach_port_t ports[EXC_TYPES_COUNT];
        exception_behavior_t behaviors[EXC_TYPES_COUNT];
        thread_state_flavor_t flavors[EXC_TYPES_COUNT];
        mach_msg_type_number_t count;
    };

    struct ios_execp_info *info = malloc(sizeof(struct ios_execp_info));

    task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, info->masks, &info->count, info->ports, info->behaviors, info->flavors);

    for (int i = 0;i < info->count; i++) {
        if (info->ports[i] != 0 || info->flavors[i] == THREAD_STATE_NONE) {
            NSLog(@"Being debugged... task_get_exception_ports");
            exit(-1);
        }else {
            NSLog(@"Bypassed task_get_exception_ports");
        }
    }
    
    /*isatty检测*/
    if (isatty(1)) {
        NSLog(@"Being Debugged isatty");
        exit(-1);
    }else {
        NSLog(@"Bypassed isatty");
    }

    /*ioctl检测 自己测试无效，不确定是否失效，有待查资料验证 */
    if (!ioctl(1, TIOCGWINSZ)) {
        NSLog(@"Being Debugged ioctl");
        exit(-1);
    }else {
        NSLog(@"Bypassed ioctl");
    }
    
    /*内联汇编反调试*/
#ifdef __arm__
    asm volatile (
                  "mov r0, #31\n"
                  "mov r1, #0\n"
                  "mov r2, #0\n"
                  "mov r12, #26\n" //ptrace
                  "svc #80\n"
                );
    NSLog(@"Bypassed syscall() ASM");
#endif
#ifdef __arm64__
    asm volatile (
                  "mov x0, #26\n"
                  "mov x1, #31\n"
                  "mov x2, #0\n"
                  "mov x3, #0\n"
                  "mov x16, #0\n" //syscall
                  "svc #128\n"
                  );
    NSLog(@"Bypassed syscall() ASM64");
#endif
    
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
