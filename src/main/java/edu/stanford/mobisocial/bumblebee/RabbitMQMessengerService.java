package edu.stanford.mobisocial.bumblebee;

import java.beans.PropertyEditorManager;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.jivesoftware.smack.packet.Message;
import org.xbill.DNS.CNAMERecord;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.ConfirmListener;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.MessageProperties;
import com.rabbitmq.client.QueueingConsumer;
import com.rabbitmq.client.ReturnListener;
import com.rabbitmq.client.AMQP.BasicProperties;
import com.rabbitmq.client.ShutdownSignalException;

import edu.stanford.mobisocial.bumblebee.util.Base64;
import edu.stanford.mobisocial.bumblebee.util.Util;

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
	
	private TreeMap<Long, OutgoingMessage> mMessages = new TreeMap<Long, OutgoingMessage>();
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
		
	public RabbitMQMessengerService(TransportIdentityProvider ident,
			ConnectionStatus status) {
		super(ident, status);
        mFormat = new MessageFormat(ident);
        
		exchangeKey = new String(encodeRSAPublicKey(ident.userPublicKey()));
		queueName = exchangeKey;
		factory = new ConnectionFactory();
	    factory.setHost("pepperjack.stanford.edu");
	    //a heartbeat is still required because the default tcp keep alive is 2hrs
	    //this means that normal connections get killed only after a very long time
	    //when changing networks
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
			        		final HashMap<Long, OutgoingMessage> pending = new HashMap<Long, OutgoingMessage>();
							reopen_channel: for(;;) {
					        	try {
					        		synchronized(conn) {
					        			if(!conn.isOpen())
					        				return;
					        			outChannel = conn.createChannel();
					        			//turn on publisher confirmation
				                    	outChannel.confirmSelect();
					        		}
					        		final HashMap<List<RSAPublicKey>, String> routes = new HashMap<List<RSAPublicKey>, String>();
			                    	outChannel.addConfirmListener(new ConfirmListener() {
										public void handleNack(long deliveryTag, boolean multiple)
												throws IOException {
											//resend if it was lost
											OutgoingMessage m = pending.get(deliveryTag);
											sendMessage(m);
											pending.remove(deliveryTag);
										}
										
										public void handleAck(long deliveryTag, boolean multiple)
												throws IOException {
											//delivered!
											OutgoingMessage m = pending.get(deliveryTag);
											m.onCommitted();
											pending.remove(deliveryTag);
											
										}
									});
				                	outChannel.addReturnListener(new ReturnListener() {
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
										}

									});
				                	next_message: for(;;) {
					                	OutgoingMessage m = null;
										try {
											synchronized (mMessages) {
												if(mMessages.isEmpty())
													mMessages.wait(15000);
												if(!mMessages.isEmpty()) {
													Long key = mMessages.firstKey();
 													m = mMessages.get(key);
													mMessages.remove(key);
												}
											}
										} catch (InterruptedException e) {
										}

										//if there is no connection or we were half shutdown, bail out
										if(!conn.isOpen() || shutdown) {
											if(m != null)
												sendMessage(m);
											break reopen_channel;
										}
										if(m == null)
											continue next_message;
														                    	
										byte[] cyphered;
										try {
											cyphered = mFormat.encodeOutgoingMessage(m);
					                    } catch(CryptoException e) {
											//TODO: should mark committed?

					                    	//just skip on crypto exception when sending
											signalConnectionStatus("Failed to handle message crypto", e);
											continue next_message;
					                    }
				                        
										//at this point, we won't be discarding this message, so pend it
										long seq = outChannel.getNextPublishSeqNo();
					                    pending.put(seq, m);

				                        List<RSAPublicKey> keys = m.toPublicKeys();
				                        String exchange = routes.get(keys);
				                        if(exchange == null) {
				                			MessageDigest sha1;
											try {
												sha1 = MessageDigest.getInstance("SHA1");
											} catch (NoSuchAlgorithmException e) {
												throw new RuntimeException("Crypto fail!", e);
											}
					                    	for(RSAPublicKey pubKey : keys){
					                    		sha1.update(pubKey.getEncoded());
					                    	}
					                    	exchange = Base64.encodeToString(sha1.digest(), false);
					                        outChannel.exchangeDeclare(exchange, "fanout");
					                    	for(RSAPublicKey pubKey : keys){
					                    		String dest = encodeRSAPublicKey(pubKey);
					                    		outChannel.queueDeclare(dest, true, false, false, null);
					                    		outChannel.queueBind(dest, exchange, "");
					                    	}
					                    	routes.put(keys, exchange);
				                        }
										signalConnectionStatus("Sending " + cyphered.length + " bytes", null);
				                        outChannel.basicPublish(exchange, "", true, false, null, cyphered);
					                }
					        	} catch(IOException e) {
					        		e.printStackTrace(System.err);
					        		//if we have to rebuild the channel, wait a bit to retry
									try {
										Thread.sleep(30000);
									} catch (InterruptedException e1) {
									}
					        		//whenever we reopen the channel or potentially reconnect, we must
					        		//add the messages back to the queue to be sent
					        		for(OutgoingMessage m : pending.values()) {
					        			sendMessage(m);
					        		}		        		
									continue reopen_channel;
					        	} catch(ShutdownSignalException e) {
					        		e.printStackTrace(System.err);
					        		//if we have to rebuild the channel, wait a bit to retry
									try {
										Thread.sleep(30000);
									} catch (InterruptedException e1) {
									}
					        		//whenever we reopen the channel or potentially reconnect, we must
					        		//add the messages back to the queue to be sent
					        		for(OutgoingMessage m : pending.values()) {
					        			sendMessage(m);
					        		}		        		
									break reopen_channel;
					        	}
					        }
							shutdown = true;
			        		synchronized(conn) {
			        			try {
									conn.close();
								} catch (Throwable e) {}
			        		}
			            }
			        };	 
			        outThread.start();
			        inThread = new Thread(new Runnable() {
						
						public void run() {
					        boolean autoAck = false;
					        reopen_channel: for(;;) {
						        try {
					        		synchronized(conn) {
					        			if(!conn.isOpen())
					        				return;
					        			inChannel = conn.createChannel();
					        		}
							        QueueingConsumer consumer = new QueueingConsumer(inChannel);
									inChannel.queueDeclare(queueName, true, false, false, null);						
							        inChannel.basicConsume(queueName, autoAck, consumer);
							        next_message: for(;;) {
							            QueueingConsumer.Delivery delivery = null;
							            try {
							                delivery = consumer.nextDelivery(15000);
							            } catch (InterruptedException ie) {
							            }
										if(!conn.isOpen() || shutdown)
											break reopen_channel;
							            if(delivery == null)
							            	continue next_message;
							            final byte[] body = delivery.getBody();
							            if(body == null) {
					                        System.err.println("Could not decode message.");
							            	inChannel.basicReject(delivery.getEnvelope().getDeliveryTag(), false);
							            	continue next_message;
							            }
					
					                    final String id = mFormat.getMessagePersonId(body);
					                    if (id == null) {
					                        System.err.println("WTF! person id in message does not match sender!.");
							            	inChannel.basicReject(delivery.getEnvelope().getDeliveryTag(), false);
							            	continue next_message;
					                    }
					                    final String contents;
					                    try {
						                    contents = mFormat.decodeIncomingMessage(body);
					                    } catch(CryptoException e) {
											signalConnectionStatus("Failed to handle message crypto", e);
											//a crypto exception will just keep happening, we need to cancel the message
							            	inChannel.basicReject(delivery.getEnvelope().getDeliveryTag(), false);
							            	continue next_message;
					                    }
			                        	long msghash;
										try {
											msghash = mFormat.extractHash(body);
										} catch (CryptoException e) {
											msghash = new Random().nextLong();
										} 
										final long fmsghash = msghash;
					                    signalMessageReceived(
					                        new IncomingMessage() {
					                            public String from() { return id; }
					                            public String contents() { return contents; }
					                            public String toString() { return contents(); }
					                            public long hash() {
					                            	return fmsghash;
					                            }
					                        });
							            inChannel.basicAck(delivery.getEnvelope().getDeliveryTag(), false);
							        }

						        } catch(IOException e) {
									signalConnectionStatus("Failed to receive message over AMQP connection", e);
									continue reopen_channel;
						        } catch(ShutdownSignalException e) {				        	
									signalConnectionStatus("Forced shutdown in receive AMQP", e);
									break reopen_channel;
					        	} finally {
					        		//if we have to rebuild the channel, wait a bit to retry
									try {
										Thread.sleep(30000);
									} catch (InterruptedException e1) {
									}
					        	}
					        }
							shutdown = true;
			        		synchronized(conn) {
			        			try {
									conn.close();
								} catch (Throwable e) {
									e.printStackTrace();
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
		//encode it ahead of time, so that future, enqueues won't change the encoded format
		//also, force the sending thread to spend the time to process it and flush
		//it to the db, otherwise we have to keep too much stuff in memory.
		try {
			mFormat.encodeOutgoingMessage(m);
			synchronized (mMessages) {
				mMessages.put(m.getLocalUniqueId(), m);
				mMessages.notify();
			}
		} catch(CryptoException e) {
			throw new RuntimeException(e);
		}
	}
	static class FixedIdentityProvider implements TransportIdentityProvider {
		FixedIdentityProvider(RSAPublicKey pub, RSAPrivateKey priv) {
			mPub = pub;
			mPriv = priv;
		}
		public RSAPublicKey userPublicKey() {
			return mPub;
		}

		public RSAPrivateKey userPrivateKey() {
			return mPriv;
		}

		public String userPersonId() {
			return Util.makePersonIdForPublicKey(mPub);
		}

		public RSAPublicKey publicKeyForPersonId(String id) {
			return null;
		}

		public String personIdForPublicKey(RSAPublicKey key) {
			return Util.makePersonIdForPublicKey(key);
		}
		RSAPublicKey mPub;
		RSAPrivateKey mPriv;
	}
	static class DummyConnectionStatus implements ConnectionStatus {
		public boolean isConnected() {
			return true;
		}
	}

	static byte[] inputStreamToByteArray(InputStream is) throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int nRead;
		byte[] data = new byte[16384];

		while ((nRead = is.read(data, 0, data.length)) != -1) {
		  buffer.write(data, 0, nRead);
		}

		buffer.flush();

		return buffer.toByteArray();
	}
	public static void main(String[] args)  
	{
		System.out.println(Arrays.toString(args));
		try {
			if(args.length == 0) {
				System.err.println("To listen for messages pass --listen myprivatekey.raw mypublickey.raw");
				System.err.println("To send a messages pass --from myprivatekey.raw mypublickey.raw destinationkey0.raw ... destinationkeyN.raw");
				System.err.println("To generate a dummy key pair --generate myprivatekey.raw mypublickey.raw");
				System.exit(1);
			}
			if(args.length < 3) {
				System.err.println("must specify personal key files");
				System.exit(1);
			}
			if(args[0].equals("--generate")) {
	            // Generate a 1024-bit Digital Signature Algorithm (RSA) key pair
	            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	            keyGen.initialize(1024);
	            KeyPair kp = keyGen.genKeyPair();        
	            
	            new FileOutputStream(args[1]).write(kp.getPrivate().getEncoded());
	            new FileOutputStream(args[2]).write(kp.getPublic().getEncoded());
				System.exit(0);
			}
			KeyFactory skf = KeyFactory.getInstance("RSA");
			RSAPrivateKey private_key = (RSAPrivateKey)skf.generatePrivate(new PKCS8EncodedKeySpec(inputStreamToByteArray(new FileInputStream(args[1])))); 
			RSAPublicKey public_key = (RSAPublicKey)skf.generatePublic(new X509EncodedKeySpec(inputStreamToByteArray(new FileInputStream(args[2])))); 
	        RabbitMQMessengerService ms = new RabbitMQMessengerService(new FixedIdentityProvider(public_key, private_key), new DummyConnectionStatus());
	        ms.addConnectionStatusListener(new ConnectionStatusListener() {
				
				public void onStatus(String msg, Exception e) {
					System.err.println("connection status: " + msg);
					if(e != null)
						e.printStackTrace(System.err);
					
				}
			});
			if(args[0].equals("--listen")) {
				ms.addMessageListener(new MessageListener() {
					public void onMessage(IncomingMessage m) {
						System.out.println("message from: " + m.from());
						System.out.println(m.contents());
					}
				});
			} else if(args[0].equals("--from")) {
				if(args.length < 4) {
					System.err.println("must specify some destination");
					System.exit(1);
				}
				final List<RSAPublicKey> to = new LinkedList<RSAPublicKey>();
				for(int i = 3; i < args.length; ++i) {
					to.add((RSAPublicKey)skf.generatePublic(new X509EncodedKeySpec(inputStreamToByteArray(new FileInputStream(args[i])))));
					RSAPublicKey x = (RSAPublicKey)skf.generatePublic(new X509EncodedKeySpec(inputStreamToByteArray(new FileInputStream(args[i]))));
				}
				for(;;) {
					final byte[] message = inputStreamToByteArray(System.in);
					ms.sendMessage(new OutgoingMessage() {
						byte[] mEncoded;
						
						public List<RSAPublicKey> toPublicKeys() {
							return to;
						}
						
						public void onEncoded(byte[] encoded) {
							mEncoded = encoded;
						}
						
						public void onCommitted() {
							System.err.println("written!");
							System.exit(0);
							
						}
						
						public long getLocalUniqueId() {
							return 0;
						}
						
						public byte[] getEncoded() {
							return mEncoded;
						}
						
						public String contents() {
							return new String(message);
						}
					});
				}
			}
		} catch(Exception e) {
			System.err.println("failure encountered");
			e.printStackTrace(System.err);
			System.exit(1);
		}
	}
}
