""" Tests all of the RabbitMQ Adapter """

import os

import pika

import rabbit


class MockPikaChannel(pika.channel.Channel):
    """Mock class for testing pika calls"""

    def __init__(self):
        # pylint: disable=super-init-not-called
        pass

    @staticmethod
    def basic_publish(exchange,
                      routing_key,
                      body,
                      properties=None,
                      mandatory=False):
        return True


class MockPikaBadAMQP(pika.channel.Channel):
    """Mock class for testing pika AMQP failures"""

    def __init__(self):
        # pylint: disable=super-init-not-called
        pass

    @staticmethod
    def basic_publish(exchange,
                      routing_key,
                      body,
                      properties=None,
                      mandatory=False):
        raise pika.exceptions.AMQPError('failure')


class MockRabbitAdapter(rabbit.RabbitAdapter):
    """Mock class for testing RabbitAdapter"""

    @staticmethod
    def rabbit_conn():
        return True

    @staticmethod
    def socket_conn():
        return True


def test_no_rabbit_host():
    """Test no rabbit host set"""
    rabbit_adapter = rabbit.RabbitAdapter()
    rabbit_adapter.main()


def test_no_rabbit_connection():
    """Test no connection available to rabbit"""
    os.environ['FA_RABBIT_HOST'] = 'localhost'
    rabbit_adapter = rabbit.RabbitAdapter()
    rabbit_adapter.main()
    assert rabbit_adapter.host == 'localhost'


def test_no_socket_path():
    """Test no socket path set"""
    rabbit_adapter = rabbit.RabbitAdapter()
    rabbit_adapter.socket_conn()


def test_no_socket_connection():
    """Test no connection available to socket"""
    os.environ['FAUCET_EVENT_SOCK'] = '1'
    rabbit_adapter = rabbit.RabbitAdapter()
    rabbit_adapter.socket_conn()
    assert rabbit_adapter.event_sock == '/var/run/faucet/faucet.sock'


def test_socket_connection():
    """Test connection available to socket"""
    os.environ['FAUCET_EVENT_SOCK'] = '/var/run/faucet/faucet-event.sock'
    rabbit_adapter = rabbit.RabbitAdapter()
    rabbit_adapter.socket_conn()
    assert rabbit_adapter.event_sock == '/var/run/faucet/faucet-event.sock'


def test_port_set_int():
    """Test port was set and it was an int"""
    os.environ['FA_RABBIT_PORT'] = '9999'
    rabbit_adapter = rabbit.RabbitAdapter()
    assert rabbit_adapter.port == 9999


def test_port_set_not_int():
    """Test port was set and it was not an int"""
    os.environ['FA_RABBIT_PORT'] = 'bad'
    rabbit_adapter = rabbit.RabbitAdapter()
    assert rabbit_adapter.port == 5672


def test_routing_key_not_set():
    """Test routing_key was not set"""
    os.environ['FA_RABBIT_ROUTING_KEY'] = ''
    rabbit_adapter = rabbit.RabbitAdapter()
    assert rabbit_adapter.routing_key == 'FAUCET.Event'


def test_routing_key_set():
    """Test routing_key was set"""
    os.environ['FA_RABBIT_ROUTING_KEY'] = 'foo'
    rabbit_adapter = rabbit.RabbitAdapter()
    assert rabbit_adapter.routing_key == 'foo'


def test_rabbit_socket_true():
    """Test if rabbit_conn and socket_conn are True"""
    rabbit_adapter = MockRabbitAdapter()
    rabbit_adapter.channel = MockPikaChannel()
    rabbit_adapter.main()


def test_amqp_failure():
    """Test if rabbit_conn throws an AMQP error"""
    rabbit_adapter = MockRabbitAdapter()
    rabbit_adapter.channel = MockPikaBadAMQP()
    rabbit_adapter.main()
