package edu.stanford.mobisocial.bumblebee;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.jivesoftware.smack.packet.Message;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.MessageProperties;
import com.rabbitmq.client.QueueingConsumer;
import com.rabbitmq.client.ReturnListener;
import com.rabbitmq.client.AMQP.BasicProperties;

import edu.stanford.mobisocial.bumblebee.util.Base64;

public class RabbitMQMessengerService extends MessengerService {

	ConnectionFactory factory;
	Connection conn;
	Channel inChannel;
	Channel outChannel;
	String exchangeKey;
	String queueName;
	Thread outThread;
	Thread inThread;
	
	private LinkedBlockingQueue<OutgoingMessage> mSendQ = 
	        new LinkedBlockingQueue<OutgoingMessage>();
	private MessageFormat mFormat = null;
	
	static String encodeRSAPublicKey(RSAPublicKey key) {
		try {
			byte[] mod = key.getModulus().toByteArray();
			byte[] exp = key.getPublicExponent().toByteArray();
			ByteArrayOutputStream bytes = new ByteArrayOutputStream();
			DataOutputStream data = new DataOutputStream(bytes);
			data.write(255);
			data.write(mod.length);
			data.write(mod);
			data.write(exp.length);
			data.write(exp);
			data.flush();
			byte[] raw = bytes.toByteArray();
			return Base64.encodeToString(raw, false);
		} catch(IOException e) {
			throw new RuntimeException(e);
		}
	}

	public RabbitMQMessengerService(TransportIdentityProvider ident,
			ConnectionStatus status) {
		super(ident, status);
        mFormat = new MessageFormat(ident);
        
		exchangeKey = new String(encodeRSAPublicKey(ident.userPublicKey()));
		queueName = exchangeKey;
		 factory = new ConnectionFactory();
	     factory.setHost("pepperjack.stanford.edu");
	     
	     try {
	        conn = factory.newConnection();
	        inChannel = conn.createChannel();
	        inChannel.exchangeDeclare(exchangeKey, "direct", true);
	        inChannel.queueDeclare(queueName, true, true, false, null);
	        inChannel.queueBind(queueName, exchangeKey, "");
	        
	        outChannel = conn.createChannel();
	        

	    } catch(IOException e) {
	    	 throw new RuntimeException(e);
	    }
     
        outThread = new Thread() {
            @Override
            public void run() {
                while (true) {
                	OutgoingMessage m = null;
                    try {
						try {
							m = mSendQ.poll(15, TimeUnit.SECONDS);
						} catch (InterruptedException e) {
						}
						if(m == null)
							continue;
                    	outChannel.exchangeDeclare(exchangeKey + ":out", "fanout");
                    	for(RSAPublicKey pubKey : m.toPublicKeys()){
                    		outChannel.exchangeDeclare(encodeRSAPublicKey(pubKey), "direct", true);
                    		outChannel.exchangeBind(encodeRSAPublicKey(pubKey), exchangeKey + ":out", "");
                    	}
                    	String plain = m.contents();
                    	byte[] cyphered = mFormat.encodeOutgoingMessage(
                    			plain, m.toPublicKeys());
                        outChannel.basicPublish(exchangeKey + ":out", "", true, false, null, cyphered);
                        outChannel.exchangeDelete(exchangeKey + ":out");
                    } catch(CryptoException e) {
                    	throw new RuntimeException(e);
                    } catch (IOException e) {
                    	mSendQ.add(m);
                    	throw new RuntimeException(e);
                    }
                }
            }
        };	 
        outThread.start();
        
        inThread = new Thread(new Runnable() {
			
			public void run() {
		        boolean autoAck = false;
		        QueueingConsumer consumer = new QueueingConsumer(inChannel);
		        try {
			        inChannel.basicConsume(queueName, autoAck, consumer);
			        for(;;) {
			            QueueingConsumer.Delivery delivery;
			            try {
			                delivery = consumer.nextDelivery();
			            } catch (InterruptedException ie) {
			                continue;
			            }
	
			            final byte[] body = delivery.getBody();
			            if(body == null) throw new RuntimeException("Could not decode message.");
	
	                    final String id = mFormat.getMessagePersonId(body);
	                    if (id == null) {
	                        System.err.println("WTF! person id in message does not match sender!.");
	                        return;
	                    }
	                    RSAPublicKey pubKey = identity().publicKeyForPersonId(id);
	                    if (pubKey == null) {
	                        System.err.println("WTF! message from unrecognized sender! " + id);
	                        return;
	                    }
			            
	                    try {
		                    final String contents = mFormat.decodeIncomingMessage(body, pubKey);
		                    signalMessageReceived(
		                        new IncomingMessage() {
		                            public String from() { return id; }
		                            public String contents() { return contents; }
		                            public String toString() { return contents(); }
		                        });
				            inChannel.basicAck(delivery.getEnvelope().getDeliveryTag(), false);
	                    } catch(CryptoException e) {
	                    	throw new RuntimeException(e);
	                    }
			        }
		        } catch(IOException e) {
		        	throw new RuntimeException(e);
		        }
			}
		});
		inThread.start();
	}

	@Override
	public void init() {
		// TODO Auto-generated method stub

	}

	@Override
	public void sendMessage(OutgoingMessage m) {
		try {
			mSendQ.put(m);
		} catch(InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

}
