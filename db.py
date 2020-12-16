import mysql.connector
import json

def stringify(val):
	return "'" + val + "'"

class MySQLDB:

	def __init__(self, host, user, passwd, database, *args, **kwargs):
		self.db = mysql.connector.connect(
			host=host, 
			user=user, 
			passwd=passwd, 
			database=database)
		self.cursor = self.db.cursor()
		print ('[+] Connection to DB successful')

	def insert_data(self, data, table):
		first = "insert into {} (".format(table)
		second = "values ("
		for key, val in data.items():
			if val != '-':
				first += key.lower().replace(' ', '_').replace("/", "or") + ', '
				second += stringify(str(val)) + ", "
		first = first.strip()[:-1] + ')'
		second = second.strip()[:-1] + ')'
		query = first + " " + second

		try:
			self.cursor.execute(query)
		except mysql.connector.errors.IntegrityError:
			return False, 'duplicate entry'
			pass
		self.db.commit()
		return True, 'success'

	def get(self, column, table):
		query = f"select {column} from {table}"
		self.cursor.execute(query)
		return [i[0] for i in self.cursor.fetchall()]

	def get_pwd_of_user(self, username, table):
		query = f"select password from {table} where username='{username}'"
		self.cursor.execute(query)
		return self.cursor.fetchall()[0][0]

	def get_device_by_id(self, id):
		query = f"select shared_key, label from devices where id={id}"
		self.cursor.execute(query)
		data = self.cursor.fetchall()[0]
		return {"shared_key" : data[0], "label" : data[1]}

	def get_existing_emails(self, table):
		query = f"select email from {table}"
		self.cursor.execute(query)
		data = self.cursor.fetchall()
		return [i[0] for i in data]

if __name__ == '__main__':
	db = MySQLDB(host="127.0.0.1", user="root", passwd="password", database="stock_features")
	# db.insert_data(data={"username" : "abdh123", "password" : "122323"}, table='users')
	# print (db.get_pwd_of_user(username="username", table="users"))

	# db.insert_data({"shared_key" : 'ponmlkjihgfedcba', 'label' : 'label'}, table="devices")

	# print (db.get_device_by_id(id=1))
	print (db.get_existing_emails("users"))

