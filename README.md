# containermigration

## Memory region of a process

### Output of cat /proc/PID/maps

#### 1. TEXT

```
00400000-004de000 r-xp 00000000 fd:02 825792                             /usr/bin/bash
```

#### 2. DATA

```
006dd000-006de000 r--p 000dd000 fd:02 825792                             /usr/bin/bash
006de000-006e7000 rw-p 000de000 fd:02 825792                             /usr/bin/bash
006e7000-006ed000 rw-p 00000000 00:00 0
```

#### 3. HEAP + Shared Library

Note that the second line for each library file (`libc-2.17.so`, `libdl-2.17.so`, `libtinfo.so.5.9`) are restricted memory regions potentially for internal use by the operating system.

```
021b7000-021d8000 rw-p 00000000 00:00 0                                  [heap]
7ff8c9052000-7ff8c9216000 r-xp 00000000 fd:02 318885                     /usr/lib64/libc-2.17.so
7ff8c9216000-7ff8c9415000 ---p 001c4000 fd:02 318885                     /usr/lib64/libc-2.17.so
7ff8c9415000-7ff8c9419000 r--p 001c3000 fd:02 318885                     /usr/lib64/libc-2.17.so
7ff8c9419000-7ff8c941b000 rw-p 001c7000 fd:02 318885                     /usr/lib64/libc-2.17.so
7ff8c941b000-7ff8c9420000 rw-p 00000000 00:00 0
7ff8c9420000-7ff8c9422000 r-xp 00000000 fd:02 321414                     /usr/lib64/libdl-2.17.so
7ff8c9422000-7ff8c9622000 ---p 00002000 fd:02 321414                     /usr/lib64/libdl-2.17.so
7ff8c9622000-7ff8c9623000 r--p 00002000 fd:02 321414                     /usr/lib64/libdl-2.17.so
7ff8c9623000-7ff8c9624000 rw-p 00003000 fd:02 321414                     /usr/lib64/libdl-2.17.so
7ff8c9624000-7ff8c9649000 r-xp 00000000 fd:02 319215                     /usr/lib64/libtinfo.so.5.9
7ff8c9649000-7ff8c9849000 ---p 00025000 fd:02 319215                     /usr/lib64/libtinfo.so.5.9
7ff8c9849000-7ff8c984d000 r--p 00025000 fd:02 319215                     /usr/lib64/libtinfo.so.5.9
7ff8c984d000-7ff8c984e000 rw-p 00029000 fd:02 319215                     /usr/lib64/libtinfo.so.5.9
7ff8c984e000-7ff8c9870000 r-xp 00000000 fd:02 319547                     /usr/lib64/ld-2.17.so
```

#### 4. STACK

```
7ff8c9a40000-7ff8c9a43000 rw-p 00000000 00:00 0
7ff8c9a6d000-7ff8c9a6f000 rw-p 00000000 00:00 0
7ff8c9a6f000-7ff8c9a70000 r--p 00021000 fd:02 319547                     /usr/lib64/ld-2.17.so
7ff8c9a70000-7ff8c9a71000 rw-p 00022000 fd:02 319547                     /usr/lib64/ld-2.17.so
7ff8c9a71000-7ff8c9a72000 rw-p 00000000 00:00 0
7fffa3acc000-7fffa3aee000 rw-p 00000000 00:00 0                          [stack]
```

#### 5. VDSO (Virtual Dynamic Shared Object) Segment + Vsyscall Segment

```
7fffa3b4d000-7fffa3b4f000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```
