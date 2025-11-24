from flask import Flask, render_template, jsonify, request, send_file
from PIL import Image
import io

app = Flask(__name__)

WIDTH, HEIGHT = 224, 224

with open('STEGosaurus.txt', 'r') as f:
    cont = f.read().strip().split()
assert len(cont) == WIDTH * HEIGHT

words = sorted(set(cont))

mapp = {w: (w.startswith('roo')) for w in words}

def make_img():
    img = Image.new('1', (WIDTH, HEIGHT))
    pix = img.load()
    for i, word in enumerate(cont):
        x = i % WIDTH
        y = i // WIDTH
        pix[x, y] = 0 if mapp[word] else 1
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf

@app.route('/')
def index():
    return render_template('index.html', width=WIDTH, height=HEIGHT, words_list=cont, unique_words=words, color_map=mapp)

@app.route('/image.png')
def image():
    buf = make_img()
    return send_file(buf, mimetype='image/png')

@app.route('/toggle_color', methods=['POST'])
def toggle_color():
    word = request.json.get('word')
    if word in mapp:
        mapp[word] = not mapp[word]
        return jsonify(success=True)
    return jsonify(success=False), 400

if __name__ == '__main__':
    app.run(debug=True)
