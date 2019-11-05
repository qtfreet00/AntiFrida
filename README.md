#### Frida检测

通过Frida内存特征对maps中elf文件进行扫描匹配特征，支持frida-gadget和frida-server

不使用frida文件名和端口进行扫描，该方式相对来说篡改比较方便，

在`https://github.com/b-mueller/frida-detection-demo`上进行了改进

上面项目仅支持frida-inject和端口扫描，frida可通过frida -l 修改远程端口bypass

新版实现可用性要高一些，测试Frida 12.7.3通过，原生不检测端口，修改端口无法bypass

编译需要在ndk 15及以上
