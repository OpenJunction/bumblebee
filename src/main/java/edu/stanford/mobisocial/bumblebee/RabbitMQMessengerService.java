package edu.stanford.mobisocial.bumblebee;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.SocketException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.jivesoftware.smack.packet.Message;
import org.xbill.DNS.CNAMERecord;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.MessageProperties;
import com.rabbitmq.client.QueueingConsumer;
import com.rabbitmq.client.ReturnListener;
import com.rabbitmq.client.AMQP.BasicProperties;
import com.rabbitmq.client.ShutdownSignalException;

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
	Thread connectThread;
	
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
	
	synchronized void teardown() {
		inChannel = null;
		outChannel = null;
		conn = null;
	}
	
	boolean shutdown;
	
	HashMap<byte[], String> pendingMessages;
	
	public RabbitMQMessengerService(TransportIdentityProvider ident,
			ConnectionStatus status) {
		super(ident, status);
        mFormat = new MessageFormat(ident);
        
        pendingMessages = new HashMap<byte[], String>();
		exchangeKey = new String(encodeRSAPublicKey(ident.userPublicKey()));
		queueName = exchangeKey;
		factory = new ConnectionFactory();
	    factory.setHost("pepperjack.stanford.edu");
	    //may want this higher for battery
	    factory.setRequestedHeartbeat(30);
	    connectThread = new Thread(new Runnable() {
			
			public void run() {
				//open the connection
				while(true) {
					try {
						conn = factory.newConnection();
					} catch(IOException e) {
						signalConnectionStatus("Failed initial AMQP connection", e);
						try {
							Thread.sleep(30000);
						} catch (InterruptedException e1) {
						}
						continue;
					}
					signalConnectionStatus("AMQP connected", null);
					shutdown = false;
					//once its opened the rabbitmq library handles reconnect
			        outThread = new Thread() {
						public void run() {
							irun();
							shutdown = true;
			        		synchronized(conn) {
			        			try {
									conn.close();
								} catch (Throwable e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
			        		}
						}
						public void irun() {
					        reconnect: for(;;) {
					        	try {
					        		synchronized(conn) {
					        			if(!conn.isOpen())
					        				return;
					        			outChannel = conn.createChannel();
					        		}
				                	outChannel.setReturnListener(new ReturnListener() {
										public void handleReturn(
												int reply_code, 
												String replyText, 
												String exchange, 
												String routingKey, 
												BasicProperties properties, 
												byte[] body) throws IOException 
										{
											if(reply_code != 200)
												signalConnectionStatus("Message delivery failure: " + Base64.encodeToString(body, false), null);
											
											//todo: understand the possible reply_code's and make sure that the message is requeued if appropriate
											//xxxx: be careful not requeue blindly or you can create an infinite cycle of packets (if they keep failing for the same reason)
											synchronized (pendingMessages) {
												pendingMessages.remove(body);
											}
											
										}

									});
				                	HashMap<byte[], String> pending = new HashMap<byte[], String>();
				                	synchronized(pendingMessages) {
					                	pending.putAll(pendingMessages);
				                	}
				                	for(byte[] data : pending.keySet()) {
					                    try {
											//if there is no connection or we were half shutdown, bail out
											if(!conn.isOpen() || shutdown) {
												return;
											}
											String to = pending.get(data);
				                    		outChannel.queueDeclare(to, true, false, false, null);						
					                        outChannel.basicPublish("", to, true, false, null, data);						                        
					                    } catch(SocketException e) {
											signalConnectionStatus("socket error in send pending AMQP", e);
											return;
								        } catch (IOException e) {
											signalConnectionStatus("Failed to send pending message over AMQP connection", e);
											try {
												Thread.sleep(30000);
											} catch (InterruptedException e1) {
											}
											break reconnect;
								        } catch(ShutdownSignalException e) {
											signalConnectionStatus("Forced shutdown in send pending over AMQP", e);
											return;
								        } 
					                }
					                for(;;) {
					                	OutgoingMessage m = null;
					                    try {
											try {
												m = mSendQ.poll(15, TimeUnit.SECONDS);
											} catch (InterruptedException e) {
											}
											//if there is no connection or we were half shutdown, bail out
											if(!conn.isOpen() || shutdown) {
												if(m != null)
													sendMessage(m);
												return;
											}
											if(m == null)
												continue;
					                    	String plain = m.contents();
					                    	byte[] cyphered = mFormat.encodeOutgoingMessage(
					                    			plain, m.toPublicKeys());
					                    	for(RSAPublicKey pubKey : m.toPublicKeys()){
					                    		String dest = encodeRSAPublicKey(pubKey);
					                    		outChannel.queueDeclare(dest, true, false, false, null);						
						                        outChannel.basicPublish("", dest, true, false, null, cyphered);
						                        synchronized(pendingMessages) {
						                        	pendingMessages.put(cyphered, dest);
						                        }
						                        
					                    	}
					                    } catch(CryptoException e) {
											signalConnectionStatus("Failed to handle message crypto", e);
											return;
					                    } catch(SocketException e) {
											signalConnectionStatus("socket error in send AMQP", e);
											if(m != null) 
												sendMessage(m);
											return;
								        } catch (IOException e) {
											signalConnectionStatus("Failed to send message over AMQP connection", e);
											if(m != null) 
												sendMessage(m);
											try {
												Thread.sleep(30000);
											} catch (InterruptedException e1) {
											}
											break;
								        } catch(ShutdownSignalException e) {
											signalConnectionStatus("Forced shutdown in send AMQP", e);
											if(m != null) 
												sendMessage(m);
											return;
								        } 
					                }
					        	} catch(IOException e) {
									try {
										Thread.sleep(30000);
									} catch (InterruptedException e1) {
									}
									break;
					        	}
					        }
			            }
			        };	 
			        outThread.start();
			        inThread = new Thread(new Runnable() {
						
						public void run() {
							irun();
							shutdown = true;
			        		synchronized(conn) {
			        			try {
									conn.close();
								} catch (Throwable e) {
									e.printStackTrace();
								}
			        		}
						}
						public void irun() {
					        boolean autoAck = false;
					        for(;;) {
						        try {
					        		synchronized(conn) {
					        			if(!conn.isOpen())
					        				return;
					        			inChannel = conn.createChannel();
					        		}
							        QueueingConsumer consumer = new QueueingConsumer(inChannel);
									inChannel.queueDeclare(queueName, true, false, false, null);						
							        inChannel.basicConsume(queueName, autoAck, consumer);
							        for(;;) {
							            QueueingConsumer.Delivery delivery = null;
							            try {
							                delivery = consumer.nextDelivery(15000);
							            } catch (InterruptedException ie) {
							            }
										if(!conn.isOpen() || shutdown)
											return;
							            if(delivery == null)
							            	continue;
							            final byte[] body = delivery.getBody();
							            if(body == null) {
					                        System.err.println("Could not decode message.");
							            	inChannel.basicReject(delivery.getEnvelope().getDeliveryTag(), false);
							            	continue;
							            }
					
					                    final String id = mFormat.getMessagePersonId(body);
					                    if (id == null) {
					                        System.err.println("WTF! person id in message does not match sender!.");
							            	inChannel.basicReject(delivery.getEnvelope().getDeliveryTag(), false);
							            	continue;
					                    }
							            
					                    final String contents = mFormat.decodeIncomingMessage(body);
					                    signalMessageReceived(
					                        new IncomingMessage() {
					                            public String from() { return id; }
					                            public String contents() { return contents; }
					                            public String toString() { return contents(); }
					                        });
							            inChannel.basicAck(delivery.getEnvelope().getDeliveryTag(), false);
							        }
			                    } catch(CryptoException e) {
									signalConnectionStatus("Failed to handle message crypto", e);
									return;
						        } catch(SocketException e) {				        	
									signalConnectionStatus("socket exception in receive AMQP", e);
									return;
						        } catch(IOException e) {
									signalConnectionStatus("Failed to receive message over AMQP connection", e);
									try {
										Thread.sleep(30000);
									} catch (InterruptedException e1) {
									}
						        } catch(ShutdownSignalException e) {				        	
									signalConnectionStatus("Forced shutdown in receive AMQP", e);
									return;
						        }
					        }
						}
					});
					inThread.start();
					for(;;) {
						try {
							inThread.join();
							break;
						} catch(InterruptedException e) {
							continue;
						}
					}
					for(;;) {
						try {
							outThread.join();
							break;
						} catch(InterruptedException e) {
							continue;
						}
					}
					inThread = null;
					outThread = null;
					conn = null;
					inChannel = null;
					outChannel = null;
					
				}
			}
		}); 
	    connectThread.start();
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
