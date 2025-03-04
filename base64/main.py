import base64


def encode_decode_base64():
    # Кодування рядка у формат Base64
    original_text = input("Введіть текст для кодування: ")

    # Перетворення тексту у байти
    original_bytes = original_text.encode('utf-8')

    # Кодування байтів у Base64
    encoded_str = base64.b64encode(original_bytes)
    print(f"Закодований рядок: {encoded_str.decode('utf-8')}")

    # Декодування Base64 назад у байти
    decoded_bytes = base64.b64decode(encoded_str)
    print(f"Декодовані байти: {decoded_bytes}")

    # Перетворення байтів назад у текст
    decoded_text = decoded_bytes.decode('utf-8')
    print(f"Звичайний текст: {decoded_text}")


# Виклик функції для кодування та декодування
encode_decode_base64()