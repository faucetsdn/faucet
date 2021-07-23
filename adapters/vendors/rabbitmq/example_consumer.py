"""Example RabbitMQ consumer for testing and development purposes"""
import datetime
import logging

import pika


def callback(chan, method, properties, body):
    """Callback that has the message that was received"""
    logging.info(" [X] %s UTC %r:%r:%r:%r",
                 str(datetime.datetime.utcnow()),
                 chan,
                 method.routing_key,
                 properties,
                 body)


def main():
    """Creates the connection to RabbitMQ as a consumer and binds to the queue
    waiting for messages
    """
    params = pika.ConnectionParameters(host="0.0.0.0", port=5672)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()

    channel.exchange_declare(exchange='topic_recs', exchange_type='topic')
    result = channel.queue_declare('faucet')
    queue_name = result.method.queue

    binding_key = "FAUCET.Event"
    channel.queue_bind(exchange='topic_recs',
                       queue=queue_name,
                       routing_key=binding_key)

    return channel, queue_name


if __name__ == "__main__":
    CHANNEL, QUEUE = main()
    CHANNEL.basic_consume(queue=QUEUE, on_message_callback=callback)
    CHANNEL.start_consuming()
