# Go的并发控制
go是在并发有着天然的优势，通过关键字go 就可以进行并发，但是在并发方面由于共享变量等问题的存在，导致在面对具体的场景的时候也需要自己具体的处理

**0x01 Goroutime**  

Goroutine，可以简单的 认为就是go中的协程，看作是轻量级线程。与线程相比，创建一个 Go 协程的成本很小

### Go 协程相比于线程的优势
1. 相比线程而言，Go 协程的成本极低。堆栈大小只有若干 kb，并且可以根据应用的需求进行增减。而线程必须指定堆栈的大小，其堆栈是固定不变的。
2. Go 协程会复用（Multiplex）数量更少的 OS 线程。即使程序有数以千计的 Go 协程，也可能只有一个线程。如果该线程中的某一 Go 协程发生了阻塞（比如说等待用户输入），那么系统会再创建一个 OS 线程，并把其余 Go 协程都移动到这个新的 OS 线程。所有这一切都在运行时进行，作为程序员，我们没有直接面临这些复杂的细节，而是有一个简洁的 API 来处理并发。
3. Go 协程使用信道（Channel）来进行通信。信道用于防止多个协程访问共享内存时发生竞态条件（Race Condition）。信道可以看作是 Go 协程之间通信的管道。我们会在下一教程详细讨论信道。

**0x02  信道**

信道是go的核心概念之一，有必要大书特书。信道（Channel）可以被认为是协程之间通信的管道。与水流从管道的一端流向另一端一样，数据可以从信道的一端发送并在另一端接收。
如果是单独的用goroutine进行并发的话，由于主进程提前推出，导致goroutine异常退出

```go
package main

import (
	"fmt"
)

func flask(){
	for i:=0; i<=5; i++{
		fmt.Println(i)
	}
}

func dji(){
	for i:=6; i<=10; i++{
		fmt.Println(i)
	}
}

func main() {
	go flask()
	go dji()

}
```

![](README/6C772ABD-D16C-4864-A44C-145AD082F42F%202.png)



一种方式是利用时间延迟推迟go主进程的退出时间
```go
package main

import (
	"fmt"
	"time"
)

func flask(){
	for i:=0; i<=5; i++{
		fmt.Println(i)
	}
}

func dji(){
	for i:=6; i<=10; i++{
		fmt.Println(i)
	}
}

func main() {
	go flask()
	go dji()

	time.Sleep(time.Second)

}
```


![](README/29DF7A37-D504-4299-BE95-0C870E496AFE%202.png)
但这种方式明显很不优雅，这就需要channel了

信道的定义

信道可以简单的额理解为一个先进先出的队列

所有信道都关联了一个类型。信道只能运输这种类型的数据，而运输其他类型的数据都是非法的。信道分为有缓冲信道(Buffered channel)和无缓冲信道(unbuffered channel)，有缓冲信道可以定义存储数据的数量，无缓冲信道只能有一个数据



定义信道的方式
```go
var channel chan int
channel := make(chan int)

i := make(chan int)//int 类型
s := make(chan string)//字符串类型
r := make(<-chan bool)//只读
w := make(chan<- []int)//只写
```


channel基本操作
```go
ch := make(chan int)

// 向channel写入数据
ch <- x

// 从channel读取数据
x <- ch

// 从channel读取数据
x = <- ch

ch := make(chan int)

//关闭channel
close(ch)

//channel 一定要初始化后才能进行读写操作，否则会永久阻塞。
```

无缓冲信道基础
```go
ch := make(chan int,0)等价于 ch := make(chan int)
```

然后利用无缓冲信道解决上面提到的主进程退出的问题

```go
package main

import "fmt"

var ch chan int = make(chan int)

func flask(){
	for i:=0; i<=5; i++{
		fmt.Println(i)
	}
	ch <- 1   // 向ch中加数据，如果没有其他goroutine来取走这个数据，那么挂起foo, 直到main函数把0这个数据拿走
}

func main() {
	go flask()
	<- ch // 从ch取数据，如果ch中还没放数据，那就挂起main线，直到foo函数中放数据为止
}
```

![](README/76E3B256-07C4-498C-A1D2-655DCE8C3A05%202.png)

无缓冲信道的几个特点 
1. 从无缓冲信道取数据，必须要有数据流进来才可以，否则当前线阻塞
2. 数据流入无缓冲信道, 如果没有其他goroutine来拿走这个数据，那么当前线阻塞
3. 无缓冲信道的大小都是0 (len(channel))

对 unbuffered channel 执行 读 操作 value := <-ch 会一直阻塞直到有数据可接收，执行 写 操作 ch <- value 也会一直阻塞直到有 goroutine 对 channel 开始执行接收，正因为如此在同一个 goroutine 中使用 unbuffered channel 会造成 deadlock

有缓冲信道可以定义信道的数量，典型的定义方式是
```go
package main

import "fmt"

func main() {

	ch :=make(chan int,1)

	ch <- 1

	fmt.Println("shadow")

	<- ch
}

```



信道的典型用法
1. 和goroutine并用

```go
package main


import (
	"fmt"
)

func main() {
	c := make(chan int)
	go func() {
		fmt.Println("goroutine message")
		c <- 1 //1
	}()
	<-c //2
	fmt.Println("main function message")
}
```

在 goroutine 中在代码 #1 处向 channel 发送了数据 1 ，在 main 中 #2 处等待数据的接收，如果 c 中没有数据，代码的执行将发生阻塞，直到有 goroutine 开始往 c 中 send value


2. select
golang 的 select 就是监听 IO 操作，当 IO 操作发生时，触发相应的动作。
go select典型用法
```go
package main

import "fmt"

func main() {
	var c1, c2, c3 chan int
	var i1, i2 int

	select {
	case i1 = <-c1:
		fmt.Printf("received ", i1, " from c1\n")
	case c2 <- i2:
		fmt.Printf("sent ", i2, " to c2\n")
	case i3, ok := (<-c3):  // same as: i3, ok := <-c3
		if ok {
			fmt.Printf("received ", i3, " from c3\n")
		} else {
			fmt.Printf("c3 is closed\n")
		}
	default:
		fmt.Printf("no communication\n")
	}
}
```


有缓冲信道用法
```go
package main

import (
	"fmt"
)

func main() {
	ch1 := make(chan int, 1)
	ch2 := make(chan int, 1)

	ch1 <- 1

	select {
	case e1 := <-ch1:
		//如果ch1通道成功读取数据，则执行该case处理语句
		fmt.Printf("1th case is selected. e1=%v", e1)
	case e2 := <-ch2:
		//如果ch2通道成功读取数据，则执行该case处理语句
		fmt.Printf("2th case is selected. e2=%v", e2)
	default:
		//如果上面case都没有成功，则进入default处理流程
		fmt.Println("default!.")
	}
}
```

![](README/B75302F0-E16B-4A2A-9B17-CFEA37B0319F%202.png)

select只能应用于channel的操作，既可以用于channel的数据接收，也可以用于channel的数据发送。如果select的多个分支都满足条件，则会随机的选取其中一个满足条件的分支

```go

package main

import (
	"fmt"
)

func main() {
	ch1 := make(chan int, 1)
	ch2 := make(chan int, 1)
	ch3 := make(chan int, 1)

	ch1 <- 1
	ch2 <- 0
	ch3 <- 5

	select {
	case e1 := <-ch1:
		//如果ch1通道成功读取数据，则执行该case处理语句
		fmt.Printf("1th case is selected. e1=%v", e1)
	case e2 := <-ch2:
		//如果ch2通道成功读取数据，则执行该case处理语句
		fmt.Printf("2th case is selected. e2=%v", e2)
	case e3 := <-ch3:
		//如果ch2通道成功读取数据，则执行该case处理语句
		fmt.Printf("3th case is selected. e3=%v", e3)

	default:
		//如果上面case都没有成功，则进入default处理流程
		fmt.Println("default!.")
	}
}
```

![](README/9647B3B7-4EF8-48A6-8247-8FCEB7943EB1%202.png)

![](README/524EBA1B-B485-426F-B3F4-0E5CF401396A%202.png)


```go
package main

import "fmt"

func main() {
	ch := make(chan int, 100)
	sign := make(chan int, 1)

	//向通道中写入数据
	for i:=0; i<100; i++{
		ch <- i
	}

	close(ch)

	go func() {
		var e int
		ok := true

		for{
			select {
			case e,ok = <- ch:
				if !ok {
					fmt.Println("End.")
					break
				}
				fmt.Printf("ch11 -> %d\n",e)
			}

			//通道关闭后退出for循环
			if !ok {
				sign <- 0
				break
			}
		}

	}()

	//惯用手法，读取sign通道数据，为了等待select的Goroutine执行。
	<- sign
}
```

![](README/E534B8CD-5301-47DE-A19F-862BCAC25CFF%202.png)

3. sync
sync自带的原生包之一，他提供了像是原子锁等并发安全的函数，现在重点讲解go sync.waitgroup
WaitGroup的用途：它能够一直等到所有的goroutine执行完成，并且阻塞主线程的执行，直到所有的goroutine执行完成。
sync.WaitGroup只有3个方法，Add()，Done()，Wait()。
其中Done()是Add(-1)的别名。简单的来说，使用Add()添加计数，Done()减掉一个计数，计数不为0, 阻塞Wait()的运行。

官方示例
```go

package main

import (
	"net/http"
	"sync"
)

func main() {
	var wg sync.WaitGroup

	var urls= []string{"http://127.0.0.1", "http://www.baidu.com/"}

	for _, url :=range urls{
		wg.Add(1) //wg计数器加一

		go func(url string) { //创建新的groutine进行执行任务
		defer wg.Done() //任务执行完-1
		http.Get(url)

		}(url)
}
	wg.Wait() //等所有任务执行完结束
}
```



## go并发解决方案一:有缓冲信道和sync.wairGroup

利用有缓冲信道控制并发数量
```go
package main

import "log"

// 模拟耗时操作
func worker(i int, ch chan int) {
	log.Println("worker", i)

	<-ch
}

func main() {

	ch := make(chan int, 2)

	for i := 0; i <= 10; i++ {
		ch <- 1
		go worker(i, ch)
	}
	close(ch)

}

```


利用waitgroup进行并发
```go
package main

import (
	"fmt"
	"sync"
	"time"
)

func worker(i int, wg *sync.WaitGroup){
	fmt.Println("started Goroutine ", i)
	time.Sleep(2 * time.Second)
	fmt.Printf("Goroutine %d ended\n", i)
	wg.Done()

}

func main() {

	var wg sync.WaitGroup

	for i:=0; i<5; i++{
		wg.Add(1)
		go worker(i, &wg)

	}

	wg.Wait()
}
```

但是这样有两个问题，一个是有时主进程提前退出导致有的子协程提前异常退出，第二个就是当并发协程的数量大于总数量的时候会导致系统不会正常运行.
当然如果用time.sleep()是可以正常结束的，当然这不是什么优雅的方法,最优雅的方法就是利用go的channel

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
)

func downloader(url string, limmter chan bool, wg  *sync.WaitGroup){
	defer wg.Done()

	fmt.Println(url)
	<-limmter
}

func main() {
	wg := &sync.WaitGroup{}

	num := runtime.NumCPU()
	channel := make(chan bool, num)

	for i:=0; i<100; i++{
		wg.Add(1)
		channel <- true
		go downloader("shadopw", channel, wg)

	}

	wg.Wait()
}
```

并发多线程http请求示例
```go
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
)



func read_file(filename string)([]string){
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Print(err)

	}

	str := string(b)
	last_resu := strings.Split(str, "\n")

	return last_resu
}



func http_get(target_url string, limmter chan bool, wg  *sync.WaitGroup) {

	defer wg.Done()

	timeout := time.Duration(time.Second)

	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequest("GET", target_url, nil)
	if err != nil {
		// log.Fatal(err)
		fmt.Println(target_url+" error")
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent","Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0")

	resp, err := client.Do(req)
	if err != nil{
		// log.Fatal(err)
		fmt.Println(target_url+" error")
		return
	}

	//resCode := resp.StatusCode
	//fmt.Println(resCode)

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// handle error
		log.Fatal(err)
		return
	}


	fmt.Println(string(body))

	<- limmter

}

func main() {
	wg := &sync.WaitGroup{}

	num := runtime.NumCPU()
	channel := make(chan bool, num)

	target_list := read_file("ip.txt")

	for _, value := range target_list{
		wg.Add(1)
		channel <- true
		go http_get(value, channel, wg)

	}

	wg.Wait()
}
```


[Go 系列教程 —— 21. Go 协程  - Go语言中文网 - Golang中文社区](https://studygolang.com/articles/12342)
[golang语言并发与并行——goroutine和channel的详细理解（一） - skh2015java的博客 - CSDN博客](https://blog.csdn.net/skh2015java/article/details/60330785)
[理解 Go channel | 三月沙](https://sanyuesha.com/2017/08/03/go-channel/)
[Golang的select/非缓冲的Channel实例详解 - 巴途Way,专注Go,PHP,C开发 - CSDN博客](https://blog.csdn.net/liuxinmingcode/article/details/49507991)
[Go并发编程总结 - 每天的表现，未来的必然！ - CSDN博客](https://blog.csdn.net/luckytanggu/article/details/79402802)
https://javasgl.github.io/goroutinue-limit/

