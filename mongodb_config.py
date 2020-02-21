import keyring 
mongodb = {

    'host':"cluster0-ueu6t.mongodb.net/test?retryWrites=true&w=majority",
    'username':"alejandrodepaz",
    # 'password':"fv3X62A6Wptb72gr" 
    'password':keyring.get_password("system", "mongodb_pw")
}