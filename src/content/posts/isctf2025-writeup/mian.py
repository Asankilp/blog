          from flask import Flask,request,render_template,redirect,url_for
import json
import pydash

app=Flask(__name__)

database={}
data_index=0
name=''

@app.route('/',methods=['GET'])
def index():
    return render_template('login.html')

@app.route('/register',methods=['GET'])
def register():
    return render_template('register.html')

@app.route('/registerV2',methods=['POST'])
def registerV2():
    username=request.form['username']
    password=request.form['password']
    password2=request.form['password2']
    if password!=password2:
        return '''
        <script>
        alert('前后密码不一致，请确认后重新输入。');
        window.location.href='/register';
        </script>
        '''
    else:
        global data_index
        data_index+=1
        database[data_index]=username
        database[username]=password
        return redirect(url_for('index'))

@app.route('/user_dashboard',methods=['GET'])
def user_dashboard():
    return render_template('dashboard.html')

@app.route('/272e1739b89da32e983970ece1a086bd',methods=['GET'])
def A272e1739b89da32e983970ece1a086bd():
    return render_template('admin.html')

@app.route('/operate',methods=['GET'])
def operate():
    username=request.args.get('username')
    password=request.args.get('password')
    confirm_password=request.args.get('confirm_password')
    if username in globals() and "old" not in password:
        Username=globals()[username]
        try:
            pydash.set_(Username,password,confirm_password)
            return "oprate success"
        except:
            return "oprate failed"
    else:
        return "oprate failed"

@app.route('/user/name',methods=['POST'])
def name():
    return {'username':user}

def logout():
    return redirect(url_for('index'))

@app.route('/reset',methods=['POST'])
def reset():
    old_password=request.form['old_password']
    new_password=request.form['new_password']
    if user in database and database[user] == old_password:
        database[user]=new_password
        return '''
        <script>
        alert('密码修改成功，请重新登录。');
        window.location.href='/';
        </script>
        '''
    else:
        return '''
        <script>
        alert('密码修改失败，请确认旧密码是否正确。');
        window.location.href='/user_dashboard';
        </script>
        '''

@app.route('/impression',methods=['GET'])
def impression():
    point=request.args.get('point')
    if len(point) > 5:
        return "Invalid request"
    List=["{","}",".","%","<",">","_"]
    for i in point:
        if i in List:
            return "Invalid request"
    return render_template(point)

@app.route('/login',methods=['POST'])
def login():
    username=request.form['username']
    password=request.form['password']
    type=request.form['type']
    if username in database and database[username] != password:
        return '''
        <script>
        alert('用户名或密码错误请重新输入。');
        window.location.href='/';
        </script>
        '''
    elif username not in database:
        return '''
        <script>
        alert('用户名或密码错误请重新输入。');
        window.location.href='/';
        </script>
        '''
    else:
        global name
        name=username    
        if int(type)==1:
            return redirect(url_for('user_dashboard'))
        elif int(type)==0:
            return redirect(url_for('A272e1739b89da32e983970ece1a086bd'))

if __name__=='__main__':
    app.run(host='0.0.0.0',port=8080,debug=False)