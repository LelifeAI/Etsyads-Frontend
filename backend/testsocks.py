from PIL import Image, ImageDraw, ImageFont
import os

def create_sock_image(size, text, output_path, text_position=(50, 50), font_size=100):
    """
    Creates an image for the socks with specified text and saves it as a JPG file.

    Parameters:
        size (tuple): The size of the image (width, height) in pixels.
        text (str): The text to be added to the image.
        output_path (str): The path to save the image.
        text_position (tuple): The position to place the text on the image.
        font_size (int): The font size of the text.
    """
    # Create a blank image with a white background
    image = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(image)

    try:
        # Load a font
        font = ImageFont.truetype("arial.ttf", font_size)
    except IOError:
        print("Defaulting to basic font. Arial not found.")
        font = ImageFont.load_default()

    # Add text to the image
    draw.text(text_position, text, fill="black", font=font)

    # Save the image
    image.save(output_path, "JPEG")
    print(f"Image saved to {output_path}")


def main():
    # Predefined input details
    quote = "Yellowstone national park"  # Example quote
    keyword = "Yellowstone"  # Example keyword
    output_folder = "output_images"

    # Ensure output directory exists
    os.makedirs(output_folder, exist_ok=True)

    # Image size (Printify requirements)
    image_size = (1348, 5657)

    # File paths for the four images
    file_paths = {
        "Front left leg": os.path.join(output_folder, "front_left_leg.jpg"),
        "Front right leg": os.path.join(output_folder, "front_right_leg.jpg"),
        "Back left leg": os.path.join(output_folder, "back_left_leg.jpg"),
        "Back right leg": os.path.join(output_folder, "back_right_leg.jpg"),
    }

    # Generate images
    create_sock_image(image_size, quote, file_paths["Front left leg"], text_position=(50, 500), font_size=150)
    for position in ["Front right leg", "Back left leg", "Back right leg"]:
        create_sock_image(image_size, f"Related to {keyword}", file_paths[position], text_position=(50, 500), font_size=150)

    print("All images created successfully!")

if __name__ == "__main__":
    main()
