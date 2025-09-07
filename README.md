# CiperVault - Steganography Web Tool

A web application that allows users to hide secret messages within images using steganography techniques. Built with Python Flask for the backend and modern HTML, CSS, and JavaScript for the frontend.

## Features

- **Encode Messages**: Hide secret text messages within images
- **Decode Messages**: Extract hidden messages from encoded images
- **Drag-and-Drop Interface**: Easy-to-use interface for uploading images
- **Responsive Design**: Works on both desktop and mobile devices
- **Modern UI**: Clean and intuitive user interface

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/steganography-tool.git
   cd steganography-tool
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

1. Start the Flask development server:
   ```bash
   python app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

## How to Use

### Encoding a Message
1. Click on the "Encode" tab if not already selected
2. Drag and drop an image or click to upload
3. Enter your secret message in the text area
4. Click the "Encode Message" button
5. Download the encoded image by clicking the "Download" button

### Decoding a Message
1. Click on the "Decode" tab
2. Drag and drop an encoded image or click to upload
3. Click the "Decode Message" button
4. The hidden message will be displayed in the text area

## How It Works

This application uses the Least Significant Bit (LSB) steganography technique to hide messages within images. The LSB method works by altering the least significant bits of the pixel values in the image to store the message data. This technique makes the changes virtually undetectable to the human eye.

## Security Notes

- The application runs locally on your machine
- No images or messages are stored on any server
- For maximum security, use PNG format as it's lossless
- The longer the message, the larger the image should be to avoid detection

## Limitations

- Works best with lossless image formats (PNG, BMP)
- Very large messages may require larger images
- Some image processing (like compression) may destroy the hidden message

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/)
- Uses [Pillow](https://python-pillow.org/) for image processing
- Modern UI built with pure CSS (no frameworks)

