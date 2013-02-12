
"""
Everyone looks nicer with a moustache!

References:
http://unlogo.googlecode.com/svn-history/r130/trunk/projects/moustachizer/src/moustachizer.cpp
http://glowingpython.blogspot.nl/2011/11/face-and-eyes-detection-in-opencv.html
https://github.com/jadonk/stache/blob/master/stache.cpp

License: Public Domain

"""

import cv
import os

__all__ = ('moustachefy')


DEBUG = False

FACE_CASCADE_FILE = "haarcascade_frontalface_default.xml"
FACE_SCALE_FACTOR = 1.2
FACE_MIN_NEIGHBOURS = 2
FACE_MIN_SIZE = (20, 20)

EYES_CASCADE_FILE = "haarcascade_mcs_eyepair_big.xml"
EYES_SCALE_FACTOR = 1.2
EYES_MIN_NEIGHBOURS = 3
EYES_MIN_SIZE = (5, 10)

MOUSTACHE_MASK = "stache-mask.png"

BASE_PATH = os.path.dirname(__file__)


face_cascade = cv.Load(os.path.join(BASE_PATH, FACE_CASCADE_FILE))
eyes_cascade = cv.Load(os.path.join(BASE_PATH, EYES_CASCADE_FILE))
moustache_mask = cv.LoadImage(os.path.join(BASE_PATH, MOUSTACHE_MASK))
storage = cv.CreateMemStorage()


def process(img):
    # Detect faces
    faces = cv.HaarDetectObjects(img, face_cascade, storage, FACE_SCALE_FACTOR, FACE_MIN_NEIGHBOURS, 0, FACE_MIN_SIZE)
    for ((x, y, w, h), n) in faces:
        face_x, face_y, face_w, face_h = x, y, w, h
        pt1 = (x, y)
        pt2 = (x+w, y+h)
        if DEBUG:
            cv.Rectangle(img, pt1, pt2, cv.RGB(255, 0, 0), 3)

        # Detect eyes
        cv.SetImageROI(img, (x, y, w, h))
        eyepairs = cv.HaarDetectObjects(img, eyes_cascade, storage, EYES_SCALE_FACTOR, EYES_MIN_NEIGHBOURS, 0, EYES_MIN_SIZE)
        cv.ResetImageROI(img)
        if len(eyepairs) == 1:
            for ((x, y, w, h), n) in eyepairs:
                eyes_x, eyes_y, eyes_w, eyes_h = face_x+x, face_y+y, w, h
                pt1 = (eyes_x, eyes_y)
                pt2 = (eyes_x+w, eyes_y+h)
                if DEBUG:
                    cv.Rectangle(img, pt1, pt2, cv.RGB(0, 255, 0), 3)
            # Moustachefy!
            mask = cv.CreateImage((face_w, eyes_h), moustache_mask.depth, moustache_mask.nChannels)
            cv.SetImageROI(img, (face_x, eyes_y+(2*eyes_h)+1, face_w, eyes_h))
            cv.Resize(moustache_mask, mask, cv.CV_INTER_LINEAR)
            cv.Sub(img, mask, img)
            cv.ResetImageROI(img)
        elif not eyepairs:
            # a different moustachefy approach, without using information from the eyes position
            mask = cv.CreateImage((face_w, face_h/6), moustache_mask.depth, moustache_mask.nChannels)
            cv.SetImageROI(img, (face_x, face_y+(face_h/6)*4, face_w, face_h/6))
            cv.Resize(moustache_mask, mask, cv.CV_INTER_LINEAR)
            cv.Sub(img, mask, img)
            cv.ResetImageROI(img)
        else:
            # more than one eyepair in a single face, please bring to Area51
            pass


def save(img, filename):
    cv.SaveImage(filename, img)


def generate_filename(base_filename):
    i = 0
    base, ext = os.path.splitext(base_filename)
    while True:
        new_filename = '%s_%d%s' % (base, i, ext)
        if not os.path.isfile(new_filename):
            return new_filename
        i += 1


def moustachefy(filename):
    image = cv.LoadImage(filename)
    process(image)
    new_filename = generate_filename(filename)
    save(image, new_filename)
    return new_filename

