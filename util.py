def dump(obj, level = 0):
    prefix = level*'*'+' ' if level > 0 else ''

    if type(obj) == dict:
        for k, v in obj.items():
            if hasattr(v, '__iter__'):
                print "%s%s" % (prefix, k)
                dump(v, level+1)
            else:
                print "%s%s : %s" % (prefix, k, v)
    elif type(obj) == list:
        for v in obj:
            if hasattr(v, '__iter__'):
                dump(v, level+1)
            else:
                print "%s%s" % (prefix, v)
    else:
        print "%s%s" % (prefix, obj)
