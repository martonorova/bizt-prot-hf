import users
import options

users.app_root = options.app_root
users.__create_home()
users.add_user_unsafe('alice', 'aaa')
users.add_user_unsafe('bob', 'bbb')
users.add_user_unsafe('charlie', 'ccc')
