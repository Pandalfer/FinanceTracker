def is_num(value):
    try:
        float(value)
        return True
    except(ValueError, TypeError):
        return False

