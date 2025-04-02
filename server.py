from flask import Flask, jsonify, request

app = Flask(__name__)

# Rota padrão: retorna uma mensagem simples
@app.route("/")
def home():
    return "Hello, World!", 200

# Rota de exemplo: ecoa dados enviados via POST
@app.route("/echo", methods=["POST"])
def echo():
    data = request.json
    return jsonify({"received": data})

if __name__ == "__main__":
    # Inicia o servidor na porta 5000 (padrão do Flask)
    app.run(debug=True)
