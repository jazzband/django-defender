from django.dispatch import Signal

username_block = Signal(providing_args=['username'])
ip_block = Signal(providing_args=['ip_address'])

class BlockSignal:
    """
    Providing a sender is mandatory when sending signals, hence
    this empty sender class.
    """
    pass

def send_username_block_signal(username):
    username_block.send(sender=BlockSignal, username=username)

def send_ip_block_signal(ip_address):
    ip_block.send(sender=BlockSignal, ip_address=ip_address)
