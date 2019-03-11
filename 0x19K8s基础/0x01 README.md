## 0x01 k8s安装
打开Docker的偏好设置

![](0x01%20README/272E4DD9-0CE7-4835-9E60-6D0F954F31F2.png)


![](0x01%20README/BC94DD54-56CB-46E7-AEFB-4CE7B1756F41.png)

之后就可以启用了

查看节点
```shell
kubectl get nodes
```

![](0x01%20README/962C35FF-20D8-480E-AC62-B68B044106DE.png)

查看集群信息
```shell
kubectl cluster-info
```

![](0x01%20README/3BD5FBFC-EF80-455A-9757-08CC816B0951.png)


查看所有组件
```shell
 kubectl get all --all-namespaces=true
```

![](0x01%20README/AB824704-B021-4A21-B6E6-2263BBF70822.png)



## 0x02 配置web界面
```shell
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v1.10.1/src/deploy/recommended/kubernetes-dashboard.yaml
```


 新建一个admin-role.yaml，然后添加内容
```shell
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: admin
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: admin
  namespace: kube-system
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin
  namespace: kube-system
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
```

```
kubectl create -f admin-role.yaml
```

![](0x01%20README/93DA08D3-EA2C-4D24-A314-8D698210ADE0.png)

获取admin-token的secret名字
```shell
$ kubectl -n kube-system get secret|grep admin-token
```
![](0x01%20README/6EB3C3E9-9C23-452A-800D-899AE55A5032.png)

获取token
```shell
$ kubectl -n kube-system describe secret  admin-token-9fljb
```


![](0x01%20README/9F82C339-87F1-451E-BCEF-D08A7BDFDE3B.png)


启动代理
```shell
kubectl proxy
```


访问web界面
```
http://localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/#!/login
```


![](0x01%20README/477F0467-C1C3-4B05-93F3-3A81ADEC0AD2.png)

![](0x01%20README/ED494A56-66D9-46EA-BEA8-A4374AC8F5FC.png)

上面黄色的有报错，只需重新执行
```shell
kubectl create serviceaccount dashboard -n default
kubectl create clusterrolebinding dashboard-admin -n default --clusterrole=cluster-admin  --serviceaccount=default:dashboard
kubectl get secret $(kubectl get serviceaccount dashboard -o jsonpath="{.secrets[0].name}") -o jsonpath="{.data.token}" | base64 --decode
```

然后拿新的token登录即可
![](0x01%20README/BDE73587-E216-4926-8983-1F9BEC4225D9.png)


## 0x03 k8s使用
Pod Pod是k8s的最基本的操作单元，包含一个或多个紧密相关的容器，类似于豌豆荚的概念。

k8s的命令行是kubectl,，类似bash下的docker,
一些常规的参数
1. kubectl run :创建并运行一个或多个容器镜像或者创建一个deployment 或job 来管理容器 
2. kubectl create : 使用文件或者标准输入的方式创建一个资源
3. kubectl delete :删除
4. kubectl get :获取信息

先从部署一个简单的镜像开始
通过kubectl run部署一个nginx镜像，对外开放端口是80
```shell
kubectl run kubernetes-nginx  --generator=run-pod/v1 --image=nginx --port=80 --replicas=2 --restart=Always
```

![](0x01%20README/A2CEE597-7727-4273-95E1-FA6DB8DE6F7F.png)


查看信息
```shell
kubectl get pods --output=wide
```
![](0x01%20README/DD18AEA3-BCD5-4ED7-8EB0-EF3A49B21C55.png)

详细信息
```shell
kubectl describe pod  kubernetes-nginx
```

![](0x01%20README/6F346C66-45D0-46A1-82DE-E18B4C900115.png)


当我们将pod创建完成后，我们访问该pod内的服务只能在集群内部通过pod的的地址去访问该服务；当该pod出现故障后，该pod的控制器会重新创建一个包括该服务的pod,此时访问该服务须要获取该服务所在的新的pod的地址去访问。对此，我们可以创建一个service，当新的pod的创建完成后，service会通过pod的label连接到该服务，我们只需通过service即可访问该服务


部署
```shell
kubectl expose deployment kubernetes-nginx --name=nginx  --port=80 --target-port=80 --protocol=TCP

```


[使用kubeconfig或token进行用户身份认证 · Kubernetes Handbook - Kubernetes中文指南/云原生应用架构实践手册 by Jimmy Song(宋净超)](https://jimmysong.io/kubernetes-handbook/guide/auth-with-kubeconfig-or-token.html)
[Kubernetes网络原理及方案_Kubernetes中文社区](https://www.kubernetes.org.cn/2059.html)
[使用YAML创建一个 Kubernetes Depolyment_Kubernetes中文社区](https://www.kubernetes.org.cn/1414.html)
[简化 Kubernetes Yaml 文件创建-云栖社区-阿里云](https://yq.aliyun.com/articles/341213?utm_content=m_39828)
[Minikube体验 - Cocowool - 博客园](https://www.cnblogs.com/cocowool/p/minikube_setup_and_first_sample.html)
[Kubernetes kubectl expose命令详解 _ Kubernetes(K8S)中文文档_Kubernetes中文社区](http://docs.kubernetes.org.cn/475.html)
[kubectl命令技巧大全 - 《Kubernetes中文指南/实践手册》 - 书栈网(BookStack.CN)](https://www.bookstack.cn/read/kubernetes-handbook/guide-kubectl-cheatsheet.md)