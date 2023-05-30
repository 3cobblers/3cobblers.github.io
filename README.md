

# 一点点记录

新电脑本地环境部署

1. 下载安装[Ruby](https://rubyinstaller.org/downloads/)。 参考[Jekyll on Windows](https://jekyllrb.com/docs/installation/windows/)
    选择默认安装即可, ridk install, 安装最后阶段选择 ```MSYS2 and MINGW development tool chain```
2. 安装jekyll: ```gem install jekyll bundler```
3. 克隆工程到本地: ```git clone https://github.com/3cobblers/3cobblers.github.io.git```
4. 更新github-pages gem: ```github-pages-update.bat```
5. 用[VSCode](https://github.com/Microsoft/vscode/)做为编辑器编写文档和同步仓库
6. 添加新文档到_posts目录
7. 双击build.bat, 浏览器打开```localhost:4000```预览测试