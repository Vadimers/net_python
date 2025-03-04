def char_to_win1251_code(char):
    # Перетворюємо символ у байт за допомогою кодування Windows-1251
    byte = char.encode('windows-1251')
    # Повертаємо числовий код байта
    return byte[0]


def code_to_binary(code):
    # Перетворюємо числовий код у двійковий рядок
    return bin(code)[2:].zfill(8)


if __name__ == "__main__":
    # Зчитуємо введення від користувача
    user_input = input("Введіть букву або символ: ")

    # Перевіряємо, чи введено лише один символ
    if len(user_input) != 1:
        print("Будь ласка, введіть лише один символ.")
    else:
        # Отримуємо код символу у кодуванні Win1251
        code = char_to_win1251_code(user_input)
        # Отримуємо двійковий код
        binary_code = code_to_binary(code)

        # Виводимо результати
        print(f"Код символу '{user_input}' у Win1251: {code}")
        print(f"Двійковий код: {binary_code}")
