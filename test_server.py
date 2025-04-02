import requests

# Teste da rota GET "/"
response = requests.get("http://127.0.0.1:5000/")
print("GET / ->", response.text)

# Teste da rota POST "/echo"
payload = {"message": "Teste prático"}
response = requests.post("http://127.0.0.1:5000/echo", json=payload)
print("POST /echo ->", response.json())
