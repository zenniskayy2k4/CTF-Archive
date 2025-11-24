# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: test.py
# Bytecode version: 3.10.0rc2 (3439)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import pygame
pygame.init()
gameWidth = 480
gameHeight = 650
black_blue = (0, 0, 100)
green = (0, 255, 0)
light_blue = (200, 200, 255)
brown = (117, 63, 43)
floor_colour = (12, 107, 20)
obstacle_colour = brown
man_image_file = pygame.image.load('man_second.png')
clock = pygame.time.Clock()
game_window = pygame.display.set_mode((gameWidth, gameHeight))
rect1 = pygame.Rect((0, gameHeight - 50, gameWidth, 50))
rect2 = pygame.Rect((120, gameHeight - 150, 60, 20))
rect3 = pygame.Rect((320, gameHeight - 200, 60, 20))
rect4 = pygame.Rect((320, gameHeight - 300, 60, 20))
rect5 = pygame.Rect((120, gameHeight - 300, 60, 20))
rect6 = pygame.Rect((50, gameHeight - 400, 60, 20))
rect7 = pygame.Rect((150, gameHeight - 520, 60, 20))
rectFinal = pygame.Rect((400, gameHeight - 550, 60, 20))
boundaries = [(rect1, gameHeight - 50, 50), (rect2, gameHeight - 150, 20), (rect3, gameHeight - 200, 20), (rect4, gameHeight - 300, 20), (rectFinal, gameHeight - 550, 20), (rect6, gameHeight - 400, 20), (rect7, gameHeight - 520, 20)]

def man(x, y):
    game_window.blit(man_image_file, (x, y))

def collided(x1, y1, w1, h1, x2, y2, w2, h2):
    if x1 < x2 + w1 and x1 + w1 > x1 and (y1 < y2 + h1) and (h1 + y1 > y2):
        return True
    return False

def text_objects(text, font):
    textSurface = font.render(text, True, black_blue)
    return (textSurface, textSurface.get_rect())

def display_message(msg, multiplier=1):
    text_font = pygame.font.Font('freesansbold.ttf', 15)
    text_surf, text_rect = text_objects(msg, text_font)
    text_rect.center = (gameWidth / 2, multiplier * gameHeight / 3)
    game_window.blit(text_surf, text_rect)
manx = 0
many = gameHeight - 65 - 50
crashed = False
rightPressed = False
leftPressed = False
leftChecked = False
jumping = False
upPressed = False
rightChecked = False
speed = 4
x_change = 0
accelerate = 1
y_change = 0
man_rectangle = pygame.Rect((manx, many, 30, 65))
t = 0.1
while not crashed:
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            crashed = True
            break
        if event.type == pygame.KEYDOWN:
            if event.key == pygame.K_LEFT:
                leftPressed = True
            if event.key == pygame.K_RIGHT:
                rightPressed = True
            if event.key == pygame.K_UP:
                upPressed = True
        elif event.type == pygame.KEYUP:
            if event.key == pygame.K_LEFT:
                leftPressed = False
            if event.key == pygame.K_RIGHT:
                rightPressed = False
            if event.key == pygame.K_UP:
                upPressed = False
    x_change = (rightPressed - leftPressed) * speed
    if x_change:
        x_change += t * (x_change // abs(x_change))
        t += 0.1
    else:
        t = 0
    if jumping:
        y_change += accelerate
        many += y_change
        man_rectangle = pygame.Rect((manx, many, 30, 65))
        for rectangle, y, height in boundaries:
            if rectangle.colliderect(man_rectangle):
                if y_change > 0:
                    many = y - 65
                    y_change = 0
                    jumping = False
                if y_change < 0:
                    many = y + height
                    y_change = 0
    elif upPressed:
        jumping = True
        y_change = -16
    man_rectangle = pygame.Rect((manx, many, 30, 65))
    if not jumping:
        many += 1
        man_rectangle = pygame.Rect((manx, many, 30, 65))
        if man_rectangle.colliderect(rectFinal):
            break
        falling = True
        for rectangle, y, height in boundaries:
            if rectangle.colliderect(man_rectangle):
                falling = False
                many -= 1
        if falling:
            jumping = True
            y_change = 0
    manx += x_change
    man_rectangle = pygame.Rect((manx, many, 30, 65))
    for rectangle in boundaries:
        rectangle = rectangle[0]
        if rectangle.colliderect(man_rectangle):
            manx -= x_change
    if manx < 0:
        manx = 0
    if manx > gameWidth - 30:
        manx = gameWidth - 30
    man_rectangle = pygame.Rect((manx, many, 30, 65))
    game_window.fill(light_blue)
    man(manx, many)
    pygame.draw.rect(game_window, floor_colour, rect1)
    for rectangle in boundaries[1:]:
        rectangle = rectangle[0]
        pygame.draw.rect(game_window, obstacle_colour, rectangle)
    pygame.draw.rect(game_window, floor_colour, rectFinal)
    pygame.display.update()
    clock.tick(60)
while not crashed:
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            crashed = True
            break
    pygame.draw.rect(game_window, light_blue, pygame.Rect((0, 0, 480, 650)))
    somemoretext = bytes((x ^ y for x, y in zip([69, 83, 248, 247, 201, 230, 244, 121, 219, 149, 77, 175, 159, 11, 129, 102, 49, 30, 62, 228, 158, 79, 255, 208, 124, 102, 127, 119, 154, 15, 145, 121, 140, 229, 51, 221, 77, 72, 73, 28, 30, 78, 225, 229, 172, 57, 45, 65, 252, 48], b'\x0eb\xcf\x8c\xf8\xb9\xc0:\xec\xe0y\xe3\xd3r\xde"\x01P\t\xbb\xd5!\xcf\xa7#W9(\xadg\xa5N\xd3\xafF\x90=\x17x)A>\xd1\xd0\x99\x08o-\xb9M'))).decode()
    display_message('You win!')
    display_message(somemoretext, 2)
    pygame.display.flip()
    clock.tick(60)
pygame.quit()
quit()