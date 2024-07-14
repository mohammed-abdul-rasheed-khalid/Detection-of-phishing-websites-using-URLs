import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle
import inputScript

# Load model
app = Flask(__name__)
model = pickle.load(open('Phishing_Website.pkl', 'rb'))

@app.route('/')
def helloworld():
    return render_template("index.html")

# Redirects to the page to give the user input URL.
@app.route('/predict')
def predict():
    return render_template('final.html')

# Fetches the URL given by the URL and passes to inputScript
@app.route('/y_predict', methods=['POST'])
def y_predict():
    '''
    For rendering results on HTML GUI
    '''
    url = request.form['URL']
    checkprediction = np.array(inputScript.main(url)).reshape(1, -1)
    prediction = model.predict(checkprediction)
    print(prediction)
    output = prediction[0]
    if output == 1:
        pred = "You are safe!! This is a Legitimate Website."
    else:
        pred = "You are on the wrong site. Be cautious!"
    return render_template('final.html', prediction_text='{}'.format(pred), url=url)

# Takes the input parameters fetched from the URL by inputScript and returns the predictions
@app.route('/predict_api', methods=['POST'])
def predict_api():
    '''
    For direct API calls through request
    '''
    data = request.get_json(force=True)
    prediction = model.y_predict([np.array(list(data.values()))])

    output = prediction[0]
    return jsonify(output)

if __name__ == "__main__":
    app.run(debug=True)
