# [应用安全——蓝天°](https://github.com/EnjunDu/Introduction-to-Cybersecurity-Lab---Application-Security)

## 实验介绍

### 实验原理

​	大多数 Web 应用程序攻击都是来源于XSS、CSRF 和 SQL 注入攻击，这些攻击通常指的是通过利用网页开发时留下的漏洞，通过巧妙的方法注入恶意指令代码到网页，使用户加载并执行攻击者恶意制造的网页程序，其中CSRF存在是指攻击者构建的恶意网站被用户访问后，返回一些攻击性代码，并发出一个请求要求访问第三方站点，从而盗用用户身份，如用户名义发送邮件、虚拟货币转账等

### 实验目的

实现本地Web攻击和防御

### 实验步骤建议

1. 安装Flask框架并启动提供的源代码

2. 访问网页并实现XSS反射型与持久型攻击

3. 使用防御方法，防范XSS攻击

4. 增加一个登录功能，设计有 SQL 注入隐患的代码，进行攻击，并且展示如何进行防范

5. 设计一个 CSRF 攻击范例

6. 【选做】防御CSRF 攻击——**如你所见，杜爹当然会做**

   ### 实验步骤细化

   1. 安装Flask框架并启动提供的源代码
      在资料目录启动终端并运行

      ```bash
      conda create --name flask python=3.10
      conda activate flask
      pip install flask
      flask run
      ```

      访问终端提示的网址

   2. 访问网页并实现XSS反射型与持久型攻击
      ![image.png](https://s2.loli.net/2024/07/03/S2ORTKytMAejcm6.png)

   3. 访问网页并实现XSS反射型与持久型攻击
      ![image.png](https://s2.loli.net/2024/07/03/42Azk5tsp9U8rQM.png)

   4. 使用防御方法，防范XSS攻击。可以通过检验输入文字，转其转为全角字符进行防御

   5. 修改app.py和index.html，使得网页增加一个登录功能。设计有 SQL 注入隐患的代码，进行攻击，并且展示如何进行防范。这里可以使用使用SQLite作为数据库
      ![image.png](https://s2.loli.net/2024/07/03/lgCdL4KqWGMIH5B.png)

   6. 设计一个 CSRF 攻击范例
      在网站不部署XSS防御时，新建一个网页作为恶意网站。
      直接访问该恶意网站时会出现跳转至原网站，且当有原网站有合法用户登录时，会成功发起反射型XSS攻击。
      ![image.png](https://s2.loli.net/2024/07/03/qabwGJEKxVpiys7.png)

   ## 实验准备

   ### 硬件环境

   ```bash
   磁盘驱动器：NVMe KIOXIA- EXCERIA G2 SSD
   NVMe Micron 3400 MTFDKBA1TOTFH
   显示器：NVIDIA GeForce RTX 3070 Ti Laptop GPU
   系统型号	ROG Strix G533ZW_G533ZW
   系统类型	基于 x64 的电脑
   处理器	12th Gen Intel(R) Core(TM) i9-12900H，2500 Mhz，14 个内核，20 个逻辑处理器
   BIOS 版本/日期	American Megatrends International, LLC. G533ZW.324, 2023/2/21
   BIOS 模式	UEFI
   主板产品	G533ZW
   操作系统名称	Microsoft Windows 11 家庭中文版
   ```

   ### 软件环境

   ```bash
   VMware Workstation Pro
   Ubuntu 18.04.6 LTS
   Kali linux
   Microsoft Windows 11 家庭中文版
   ```

   ## 实验开始

   1. 先打开终端运行sudo apt install python3安装python3环境

   2. 先采用`sudo apt update`和sudo apt install python3-flask -y来安装Flask框架

   3. 在kali中创建topic13文件夹，包含已经给出的代码资料
      ![image.png](https://s2.loli.net/2024/07/03/mdVikAz1RLWUCKv.png)

   4. 在终端上输入命令 python app.py，来运行app.py，出现如下图片即表示运行成功。可通过在浏览器访问地址localhost:5000或者127.0.0.1:5000来访问该地址![image.png](https://s2.loli.net/2024/07/03/Mw3Xl8pzHLcexiy.png)

   5. 现在首先进行XSS反射型实验：在地址上输入`http://127.0.0.1:5000/?content=<script>alert('XSS反射实验成功！')</script>&submit=`提交，当显示如下弹窗时，则证明攻击成功
      ![image.png](https://s2.loli.net/2024/07/03/IiRQ5lsuX9v7bGL.png)

   6. 现在执行XSS持久型实验：在评论栏输入代码

      ```html
      <a href="#" onclick="window.location='https://www.yuanshen.com';">XSS持久型攻击——原神，启动！</a>
      ```

      后点击提交新评论，此时网址https://www.yuanshen.com便已经被存储在评论XSS持久型攻击——原神，启动！里面了。点击该评论跳转原神官网，攻击成功！![image.png](https://s2.loli.net/2024/07/03/V5Y2ARQsaxXcdDO.png)

      ![image.png](https://s2.loli.net/2024/07/03/ir1c6WLpdB74UKe.png)

   7. 现在修改app.py的代码来防止XSS攻击，修改后代码如下:

      修改地方如下：

      ```python
      from flask import Flask, render_template, request, escape
      from werkzeug.utils import escape
      
      app = Flask(__name__)
      
      # 假设的评论数据集
      dataset = ["BIT网络安全课程真有趣", "Web安全演示实验打卡", "祝同学们都能取得好成绩!"]
      
      @app.route("/", methods=["GET", "POST"])
      def index():
          query = ""
          if request.method == "POST":
              if request.form.get("submit") == "提交新评论":
                  # 通过 escape 函数转义用户输入
                  comment = escape(request.form.get("newComment").strip())
                  if comment:
                      dataset.append(comment)
          elif request.method == "GET":
              if request.args.get("submit") == "提交":
                  # 对查询参数进行转义以防止反射型XSS攻击
                  query = escape(request.args.get("content").strip())
                  if query:
                      sub_dataset = [x for x in dataset if query.lower() in x.lower()]
                      return render_template("index.html", query=query, comments=sub_dataset)
          # 默认情况下渲染页面，展示所有评论
          return render_template("index.html", query=query, comments=dataset)
      
      if __name__ == "__main__":
          app.run()
      
      ```

      

      * 使用了“escape”函数来转义用户输入
      * 对POST请求中的‘comment’进行转义
      * 对GET请求中的‘query’进行转义

      原因：转义可以将用户输入中的特殊HTML字符（如 <, >, &, " 等）转换为它们的HTML实体形式（例如，< 转换为 <）。这意味着当浏览器渲染这些转义后的字符时，它们不会被作为HTML标签或JavaScript代码执行，而是作为普通文本显示。这样，即使用户输入了 <script>alert('XSS')</script> 这样的代码，它也只会被显示出来，而不会执行

      原因：
      （1）**防止反射型XSS攻击：** 通过对URL参数（如搜索查询）进行转义，即使攻击者试图通过构造含有恶意脚本的URL来发起反射型XSS攻击，这些脚本也不会执行。因为在HTML中，这些脚本已被转义，不会被浏览器解释为代码

      （2）**防止持久型XSS攻击：** 通过对用户提交的评论内容进行转义，即使攻击者在评论中嵌入了JavaScript代码，这些代码也只会作为普通文本被存储和显示，而不会在其他用户浏览评论时执行。这样，就算这些评论包含了恶意代码，也不会对其他用户造成威胁

      **测试：**输入代码

      ```html
      http://127.0.0.1:5000/?content=<script>alert('XSS反射实验成功！')</script>&submit=提交
      ```

      后，显示`“查询评论<script>alert('XSS反射实验成功！')</script>”`，故该代码未被执行，防止反射型XSS攻击成功!
      ![image.png](https://s2.loli.net/2024/07/03/LJCDIHqz2f3kK7T.png)

      在评论栏输入代码

      ```html
      <a href="#" onclick="window.location='https://www.yuanshen.com';">XSS持久型攻击——原神，启动！</a>
      ```

      后，点击提交新评论，显示得到如下评论，故可知道转义后的代码不会被执行，代码会被当做纯文本显示在评论上。**防止XSS持久型攻击成功**！

      ![image.png](https://s2.loli.net/2024/07/03/oeh6iEVf2LRJuCk.png)

   8.  在终端输入命令python -c "import sqlite3"来导入sqlite3模块

   9. 在Flask中创建一个名为‘init_db.py’的Python文件，然后运行该文件创建初始化数据库和用户表‘login.db’。这里创建了一个初始账户，账号为sky，密码为sky666.
      源码如下:

      ```python
      import sqlite3
      
      connection = sqlite3.connect('login.db')
      cursor = connection.cursor()
      
      # 创建一个用户表
      cursor.execute('''
      CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)
      ''')
      
      # 插入示例用户
      cursor.execute('''
      INSERT INTO users(username, password) VALUES ('sky', 'sky666')
      ''')
      
      connection.commit()
      connection.close()
      ```

   10. 创建一个login.html，增加登录和注册功能，源码如下:

       ```html
       <!DOCTYPE html>
       <html lang="en">
       <head>
           <meta charset="UTF-8">
           <title>Web安全实验</title>
       </head>
       <body>
           <h2>Web安全实验</h2>
           <form action="" method="post">
               Username: <input type="text" name="username"><br>
               Password: <input type="password" name="password"><br>
               <input type="submit" value="Login">
           </form>
           <a href="/register">Register</a>
           {% if error %}
               <p style="color: red">{{ error }}</p>
           {% endif %}
       </body>
       </html>
       
       ```

       

   11. 再创建一个register.html，增加注册功能，源码如下：

       ```html
       <!DOCTYPE html>
       <html lang="en">
       <head>
           <meta charset="UTF-8">
           <title>Register</title>
       </head>
       <body>
           <h2>Register</h2>
           <form action="/register" method="post">
               Username: <input type="text" name="newUsername"><br>
               Password: <input type="password" name="newPassword"><br>
               <input type="submit" value="Register">
           </form>
       </body>
       </html>
       
       ```

       

   12. 修改index.html，增加退出登录功能

   13. 修改app.py函数，代码原理：首先进入链接后检测是否成功登陆，如果没有成功登陆则跳转login.html，login.html包含login和register，如果没有账号可以点击register跳转register.html来进行注册。然后在login输入账号密码登录成功后跳转index.html，index.html李有logout选项，点击Logout后会退出登录返回到login.html中。源码如下：

       ```python
       from flask import Flask, render_template, request, redirect, url_for, session
       import sqlite3
       from werkzeug.utils import escape
       
       app = Flask(__name__)
       app.secret_key = 'fan_xing_yu_is_little_boy_mother'
       
       # 假设的评论数据集
       dataset = ["BIT网络安全课程真有趣", "Web安全演示实验打卡", "祝同学们都能取得好成绩!"]
       
       # 注册功能
       @app.route('/register', methods=['GET', 'POST'])
       def register():
           if request.method == 'POST':
               new_username = request.form['newUsername']
               new_password = request.form['newPassword']
               connection = sqlite3.connect('login.db')
               cursor = connection.cursor()
               cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_username, new_password))
               connection.commit()
               connection.close()
               return redirect(url_for('login'))
           return render_template('register.html')
       
       @app.route("/", methods=["GET", "POST"])
       def index():
           if not session.get('logged_in'):  # 检查用户是否登录
               return redirect(url_for('login'))  # 未登录，重定向到登录页面
           query = ""
           if request.method == "POST":
               if request.form.get("submit") == "提交新评论":
                   comment = escape(request.form.get("newComment").strip())
                   if comment:
                       dataset.append(comment)
           elif request.method == "GET":
               if request.args.get("submit") == "提交":
                   query = escape(request.args.get("content").strip())
                   if query:
                       sub_dataset = [x for x in dataset if query.lower() in x.lower()]
                       return render_template("index.html", query=query, comments=sub_dataset)
           return render_template("index.html", query=query, comments=dataset)
       
       @app.route('/login', methods=['GET', 'POST'])
       def login():
           error = None
           if request.method == 'POST':
               # 从表单中获取用户名和密码
               username = request.form['username']
               password = request.form['password']
               connection = sqlite3.connect('login.db')
               cursor = connection.cursor()
       
               # 故意引入 SQL 注入的隐患（仅作为演示，实际中不应这么做）
               query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
               cursor.execute(query)
       
               user = cursor.fetchone()
               connection.close()
               if user:
                   session['logged_in'] = True
                   return redirect(url_for('index'))
               else:
                   error = "Invalid username or password"
           return render_template('login.html', error=error)
       
       @app.route('/logout')
       def logout():
           session.pop('logged_in', None)
           return redirect(url_for('login'))
       
       if __name__ == "__main__":
           app.run(debug=True)
       ```

       

   14. SQL注入攻击演示
       打开app.py后，在login里的username中输入`' OR '1'='1' --`，在password中可以不作任何输入，点击登录，可以发现，页面直接跳转到了index.html。

   15. 原理分析：
       最开始的判定代码为：`‘SELECT * FROM users WHERE username = '{username}' AND password = '{password}'’`，当我们输入' OR '1'='1' --后，代码就变为了`‘SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '任意值'’`。

       ' OR '：这个片段是试图打破原有 SQL 查询的逻辑，通过添加一个总是为真的条件（'1'='1'）。
        此时我们可以知道，‘1’=‘1’永远判定为真

       ‘--’：这是 SQL 中的注释标记。在这个上下文中，它的作用是注释掉 SQL 语句的剩余部分，特别是与密码相关的那部分，这样 SQL 服务器就不会检查密码是否正确。

   16. #### SQL防御：

       在app.py里将login函数修改为：

       ```python
       @app.route('/login', methods=['GET', 'POST'])
       def login():
           error = None
           if request.method == 'POST':
               username = request.form['username']
               password = request.form['password']
               connection = sqlite3.connect('login.db')
               cursor = connection.cursor()
       
               # 使用参数化查询防止 SQL 注入
               cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
       
               user = cursor.fetchone()
               connection.close()
               if user:
                   session['logged_in'] = True
                   return redirect(url_for('index'))
               else:
                   error = "Invalid username or password"
           return render_template('login.html', error=error)
       ```

       再次运行后，输入' OR '1'='1' --后发现显示Invalid username or password

   17. **原理分析**：为了防御SQL攻击，我们应该避免直接将用户的输入拼接到SQL查询中。故我采用参数化查询，这种方式可以确保传入的参数不会被解释为 SQL 代码的一部分，而是作为数据处理。在上述login函数的修改中，我使用参数化查询替代字符串格式化。
          这么设置的好处是应用程序不再对 SQL 注入攻击易受攻击，因为用户输入被安全地处理为查询的一部分，而不是作为 SQL 代码执行。

   18. #### CSRF攻击设计：

       设计CSRF_attack.html源码如下：

       ```html
       <!DOCTYPE html>
       <html>
       <head>
           <title>恶意网站</title>
       </head>
       <body>
           <script>
               // 构建目标网站的URL，包括恶意的XSS代码
               var targetUrl = "http://127.0.0.1:5000/?content=%3Cscript%3Ealert('XSS%E5%8F%8D%E5%B0%84%E5%AE%9E%E9%AA%8C%E6%88%90%E5%8A%9F%EF%BC%81')%3C%2Fscript%3E&submit=%E6%8F%90%E4%BA%A4";
       
               // 利用Image对象发起GET请求，绕过同源策略
               var img = new Image();
               img.src = targetUrl;
           </script>
       </body>
       </html>
       ```

       

   19. 该源码使用转义，将想要输入的ur`l“http://127.0.0.1:5000/?content=<script>alert('XSS反射实验成功！')</script>&submit=提交”`转义为“`"http://127.0.0.1:5000/?content=%3Cscript%3Ealert('XSS%E5%8F%8D%E5%B0%84%E5%AE%9E%E9%AA%8C%E6%88%90%E5%8A%9F%EF%BC%81')%3C%2Fscript%3E&submit=%E6%8F%90%E4%BA%A4";`”
       
       

   20. **构造思路**：构建恶意URL：targetUrl变量中存储了目标网站的URL，其中包括了一个查询参数content。这个参数通过URL编码嵌入了恶意的JavaScript代码，这段代码是<script>alert('XSS反射实验成功！')</script>。当目标网站接收到这个请求并处理content参数时，假设它没有对这个参数进行适当的清理或转义，那么这段JavaScript代码将在用户的浏览器中执行。

       利用Image对象发起GET请求：通过创建一个Image对象并将其src属性设置为构建好的恶意URL，实际上发起了一个对目标URL的GET请求。这个请求是在不需要用户交互的情况下自动完成的。由于是通过<img>标签加载资源的方式，它可以绕过一些简单的同源策略限制。

   21. 结果展示：在运行app.py后浏览器打开CSRF_attack.html，可以发现app.py终端显示被XSS反射型攻击成功：![image.png](https://s2.loli.net/2024/07/03/ZybtVQejqlP7Ghz.png)

   22. ### 选做之如何防御CSRF攻击

       为了防御CSRF攻击，需要使用POST请求而不是GET，并且实施CSRF保护

   23. 首先在终端运行pip install Flask-WTF来下载Flask-WTF 进行 CSRF 保护

   24. 接着修改app.py代码如下

       ```python
       from flask import Flask, render_template, request, session, redirect, url_for
       from flask_wtf import FlaskForm
       from wtforms import StringField, SubmitField
       from flask_wtf.csrf import CSRFProtect
       
       app = Flask(__name__)
       app.config['SECRET_KEY'] = 'fan_xing_yu_is_little_boy_mother'
       csrf = CSRFProtect(app)
       
       # 定义评论表单类
       class CommentForm(FlaskForm):
           newComment = StringField('评论')
           submit = SubmitField('提交新评论')
       
       dataset = ["BIT网络安全课程真有趣", "Web安全演示实验打卡", "祝同学们都能取得好成绩!"]
       
       @app.route("/", methods=["GET", "POST"])
       def index():
           form = CommentForm()
           if form.validate_on_submit():
               comment = form.newComment.data.strip()
               if comment:
                   dataset.append(comment)
               return redirect(url_for('index'))
           query = request.args.get('content', '')
           sub_dataset = [x for x in dataset if query.lower() in x.lower()]
           return render_template("index.html", form=form, comments=sub_dataset, query=query)
       
       if __name__ == "__main__":
           app.run(debug=True)
       ```

       

   25. 修改index.html代码如下：

       ```html
       <!DOCTYPE html>
       <html lang="en">
       <head>
           <meta charset="UTF-8">
           <title>Web安全实验</title>
       </head>
       <body>
           <h1>Web安全实验</h1>
           <h2>查询评论</h2>
           <form action="" method="get">
               搜索内容：<input type="text" name="content" placeholder="搜索内容">
               <input type="submit" name="submit" value="提交"> 
           </form>
           {% if query %}
           <h4>查询评论 "{{ query }}" 结果如下：</h4>
           {% else %}
           <h4>所有的评论如下：</h4>
           {% endif %}
           {% for comment in comments %}
           <div>{{ comment }}</div>
           <br>
           {% endfor %}
           <h2>发布评论</h2>
           <form action="" method="post">
               {{ form.hidden_tag() }}
               {{ form.newComment.label }}: {{ form.newComment(size=20) }}<br>
               {{ form.submit() }}
           </form>
       </body>
       </html>
       ```

       

   26. 在这个修改后的版本中，我们使用了 Flask-WTF 来定义一个简单的表单，它自动包括 CSRF 保护。{{ form.hidden_tag() }} 负责渲染 CSRF 令牌字段。这样，每次用户提交表单时，Flask-WTF 将验证 CSRF 令牌，确保请求是合法的，从而防御 CSRF 攻击。

       我们此时运行app.py后再点击CSRF_attack.py，显示攻击失败

   ## 结论与体会

   ​	通过本次实验，我深入理解了 Web 安全中几种常见攻击方式：XSS 和 CSRF，以及 SQL 注入的概念和防御策略。通过实际操作实验，我不仅加深了对这些概念的认识，也学会了如何在实际开发中应用相关防御技术。

   ​	XSS 攻击及防御：通过构造特殊的 URL 或输入恶意脚本代码到评论中，我成功模拟了反射型和持久型 XSS 攻击。这一过程让我认识到了用户输入验证和转义的重要性。通过使用 escape 函数转义用户输入，我学会了一种有效防御 XSS 攻击的方法。这个方法能够防止恶意脚本执行，保护网站和用户免受攻击。

   ​	SQL 注入及防御：我通过在登录框中输入特殊的 SQL 语句成功实现了 SQL 注入攻击，绕过了登录验证。攻击成功后，通过修改代码，采用参数化查询的方式，我学会了如何防御 SQL 注入攻击。这种方法通过将输入作为参数传递给 SQL 语句，有效避免了恶意输入被解释执行的风险。

   ​	CSRF 攻击及防御：我尝试通过构造恶意网页自动提交表单的方式发起 CSRF 攻击，但最终通过引入 Flask-WTF 提供的 CSRF 保护机制成功防御了这种攻击。通过实验，我了解到 CSRF 令牌的作用及其在 Web 应用安全中的重要性。

   ​	安全意识的重要性：作为一名 Web 开发者，必须具备安全意识，了解常见的 Web 攻击方式和防御策略，这对于开发安全的 Web 应用至关重要。

   ​	持续学习和实践：随着 Web 技术的发展，新的安全威胁不断出现。只有不断学习和实践，才能有效地应对这些安全挑战。

   ​	工具和库的作用：Flask-WTF 等工具和库提供了方便的防御机制，如 CSRF 保护、用户输入的转义等，能够大大提高开发效率和应用安全性。合理利用这些工具和库，可以让我们更加专注于业务逻辑的开发。

   ​	安全策略的综合运用：在实际开发中，应综合运用各种安全策略，如输入验证、参数化查询、使用 HTTPS、设置合理的 HTTP 安全头等，来构建一个多层次的安全防御体系。

   ​	通过本次实验，我不仅掌握了一些具体的防御技术，也对 Web 安全的重要性有了更深刻的认识。在未来的学习和工作中，我将继续关注 Web 安全领域的最新动态，不断提高自己的安全防御能力。
