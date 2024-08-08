import base64

# Replace these with your actual credentials
username = 'postmaster@sandbox9b4e72ac48bb44c6b11848558d20daa5.mailgun.org'
password = '75ba2f8ff9de072438dc9ecbab2d237b-0f1db83d-89629a56'

encoded_username = base64.b64encode(username.encode()).decode()
encoded_password = base64.b64encode(password.encode()).decode()

print("Encoded Username:", encoded_username)
print("Encoded Password:", encoded_password)
