from random import randint

def generate():
  lower = "abcdefghijklmnopqrstuvwxyz"
  upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  symbols = "!@#$%^&*()<>?[]\|"

  password = []

  for i in range(15):
    my_int = randint(0,25)

    password.append(lower[my_int])

  index1 = randint(0,14)
  index2 = randint(0,14)

  while index2 == index1:
    index2 = randint(0,14)

  my_int = randint(0,25)
  my_int2 = randint(0,16)

  password[index1] = upper[my_int]
  password[index2] = symbols[my_int2]

  final = ""

  for letter in password:
    final += letter

  return final
