package com.m15.clicknbuy.service.impl;

import java.security.Principal;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;

import com.m15.clicknbuy.dao.UserDao;
import com.m15.clicknbuy.dto.PasswordDto;
import com.m15.clicknbuy.dto.UserDto;
import com.m15.clicknbuy.entity.CartItem;
import com.m15.clicknbuy.entity.Order;
import com.m15.clicknbuy.entity.OrderItem;
import com.m15.clicknbuy.entity.Product;
import com.m15.clicknbuy.entity.User;
import com.m15.clicknbuy.repository.CartItemRepository;
import com.m15.clicknbuy.repository.OrderItemRepository;
import com.m15.clicknbuy.repository.OrderRepository;
import com.m15.clicknbuy.repository.ProductRepository;
import com.m15.clicknbuy.service.UserService;
import com.m15.clicknbuy.util.OtpSender;
import com.razorpay.RazorpayClient;
import com.razorpay.RazorpayException;
import com.razorpay.Utils;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;

@Service
public class UserServiceImpl implements UserService {

	private static final SecureRandom RANDOM = new SecureRandom();

	@Autowired
	UserDao userDao;

	@Autowired
	ProductRepository productRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	CartItemRepository itemRepository;

	@Value("${razorpay.id}")
	private String razorpayKeyId;

	@Value("${razorpay.secret}")
	private String razorpayKeySecret;

	@Autowired
	OtpSender otpSender;

	@Autowired
	OrderItemRepository orderItemRepository;

	@Autowired
	OrderRepository orderRepository;

	private int generateOtp() {
		return 100000 + RANDOM.nextInt(900000);
	}

	private double cartTotal(List<CartItem> items) {
		double total = items.stream().mapToDouble(i -> i.getProduct().getPrice() * i.getQuantity()).sum();
		return Math.round(total * 100.0) / 100.0;
	}

	@Override
	public String registerUser(UserDto userDto, BindingResult result, HttpSession session) {
		if (!userDto.getPassword().equals(userDto.getConfirmPassword()))
			result.rejectValue("confirmPassword", "error.confirmPassword",
					"* Password and Confirm Password Should be Same");
		if (userDao.emailExists(userDto.getEmail()))
			result.rejectValue("email", "error.email", "* Email Should be Unique");
		if (userDao.mobileExists(userDto.getMobile()))
			result.rejectValue("mobile", "error.mobile", "* Mobile Number Should be Unique");

		if (result.hasErrors())
			return "register.html";

		int otp = generateOtp();

		User user = new User();
		user.setName(userDto.getName());
		user.setEmail(userDto.getEmail());
		user.setPassword(encoder.encode(userDto.getPassword()));
		user.setMobile(userDto.getMobile());
		user.setGender(userDto.getGender());
		user.setOtp(otp);
		user.setVerified(false);
		user.setRole("ROLE_USER");
		user.setCreatedTime(LocalDateTime.now());

		// Save first, so no OTP is sent for an account that failed to save
		userDao.save(user);

		otpSender.sendOtpThruEmail(userDto.getEmail(), otp, userDto.getName());
		otpSender.sendOtpThruMobile(userDto.getMobile(), otp, userDto.getName());

		session.setAttribute("success", "Otp Sent Success");
		session.setAttribute("id", user.getId());
		return "redirect:/otp";
	}

	@Override
	public String confirmOtp(Long id, int otp, HttpSession session) {
		User user = userDao.findById(id);
		if (user.getOtp() == otp) {
			if (user.getCreatedTime().plusMinutes(5).isAfter(LocalDateTime.now())) {
				user.setVerified(true);
				user.setOtp(0);
				userDao.save(user);
				session.setAttribute("success", "Account Created Success");
				return "redirect:/login";
			} else {
				session.setAttribute("id", user.getId());
				session.setAttribute("error", "Otp Expired, try resending");
				return "redirect:/otp";
			}
		} else {
			session.setAttribute("id", user.getId());
			session.setAttribute("error", "Invalid OTP , Try Again");
			return "redirect:/otp";
		}
	}

	@Override
	public String resendOtp(Long id, HttpSession session) {
		User user = userDao.findById(id);
		int otp = generateOtp();
		user.setOtp(otp);
		user.setCreatedTime(LocalDateTime.now());
		userDao.save(user);

		otpSender.sendOtpThruEmail(user.getEmail(), otp, user.getName());
		otpSender.sendOtpThruMobile(user.getMobile(), otp, user.getName());

		session.setAttribute("success", "Otp Re-sent Success");
		session.setAttribute("id", user.getId());
		return "redirect:/otp";
	}

	@Override
	public String forgotPassword(String email, HttpSession session) {
		Optional<User> opUser = userDao.findByEmail(email);
		if (opUser.isEmpty()) {
			session.setAttribute("error", "No Account with entered Email");
			return "redirect:/forgot-password";
		}
		User user = opUser.get();
		int otp = generateOtp();
		user.setOtp(otp);
		user.setCreatedTime(LocalDateTime.now());
		userDao.save(user);

		otpSender.sendOtpThruEmail(user.getEmail(), otp, user.getName());

		session.setAttribute("success", "Otp Sent Success");
		session.setAttribute("id", user.getId());
		return "redirect:/reset-password";
	}

	@Override
	public String resetPassword(@Valid PasswordDto passwordDto, BindingResult result, HttpSession session, Long id,
			ModelMap map) {
		if (passwordDto.getPassword() != null && !passwordDto.getPassword().equals(passwordDto.getConfirmPassword()))
			result.rejectValue("password", "error.password", "* Password and Confirm Password Should Match");

		if (result.hasErrors()) {
			map.put("id", id);
			return "reset-password.html";
		}

		User user = userDao.findById(id);
		if (passwordDto.getOtp() != null && user.getOtp() == passwordDto.getOtp()) {
			if (user.getCreatedTime().plusMinutes(5).isAfter(LocalDateTime.now())) {
				user.setPassword(encoder.encode(passwordDto.getPassword()));
				user.setOtp(0);
				user.setVerified(true);
				userDao.save(user);
				session.setAttribute("success", "Password Reset Success");
				return "redirect:/login";
			} else {
				session.setAttribute("id", user.getId());
				session.setAttribute("error", "Otp Expired, Retry");
				return "redirect:/reset-password";
			}
		} else {
			session.setAttribute("id", user.getId());
			session.setAttribute("error", "Invalid OTP , Try Again");
			return "redirect:/reset-password";
		}
	}

	@Override
	@Transactional
	public String addToCart(Long id, HttpSession session, Principal principal) {
		Product product = productRepository.findById(id).orElseThrow();
		if (product.getStock() <= 0) {
			session.setAttribute("error", "OUT OF STOCK");
			return "redirect:/";
		}

		User user = userDao.findByEmail(principal.getName()).orElseThrow();
		List<CartItem> items = itemRepository.findByUser(user);

		boolean found = false;
		for (CartItem item : items) {
			if (item.getProduct().getId().equals(product.getId())) {
				item.setQuantity(item.getQuantity() + 1);
				itemRepository.save(item);
				found = true;
				break;
			}
		}

		if (!found) {
			CartItem item = new CartItem();
			item.setUser(user);
			item.setProduct(product);
			item.setQuantity(1);
			itemRepository.save(item);
		}

		product.setStock(product.getStock() - 1);
		productRepository.save(product);

		session.setAttribute("success", "Product Added to Cart");
		return "redirect:/user/cart";
	}

	@Override
	public String viewCart(HttpSession session, Principal principal, ModelMap map) {
		User user = userDao.findByEmail(principal.getName()).orElseThrow();
		List<CartItem> items = itemRepository.findByUser(user);

		if (items.isEmpty()) {
			session.setAttribute("error", "No Products in Cart");
			return "redirect:/";
		}

		if (session.getAttribute("success") != null) {
			map.put("success", session.getAttribute("success"));
			session.removeAttribute("success");
		}
		if (session.getAttribute("error") != null) {
			map.put("error", session.getAttribute("error"));
			session.removeAttribute("error");
		}

		map.put("items", items);
		map.put("total", cartTotal(items));
		return "cart.html";
	}

	@Override
	@Transactional
	public String increase(HttpSession session, Long id, ModelMap map) {
		CartItem item = itemRepository.findById(id).orElseThrow();
		Product product = item.getProduct();

		if (product.getStock() > 0) {
			item.setQuantity(item.getQuantity() + 1);
			itemRepository.save(item);
			product.setStock(product.getStock() - 1);
			productRepository.save(product);
			session.setAttribute("success", "Item Increased Success");
		} else {
			session.setAttribute("error", "Not Enough Stock");
		}
		return "redirect:/user/cart";
	}

	@Override
	@Transactional
	public String decrease(HttpSession session, Long id, ModelMap map) {
		CartItem item = itemRepository.findById(id).orElseThrow();
		Product product = item.getProduct();

		if (item.getQuantity() > 1) {
			item.setQuantity(item.getQuantity() - 1);
			itemRepository.save(item);
			session.setAttribute("success", "Item Decreased Success");
		} else {
			itemRepository.delete(item);
			session.setAttribute("success", "Item Removed from Cart");
		}

		// Stock goes back in both cases (it was not restored when the item was removed)
		product.setStock(product.getStock() + 1);
		productRepository.save(product);

		return "redirect:/user/cart";
	}

	@Override
	public String checkout(HttpSession session, Principal principal, ModelMap map) {
		User user = userDao.findByEmail(principal.getName()).orElseThrow();
		List<CartItem> items = itemRepository.findByUser(user);

		if (items.isEmpty()) {
			session.setAttribute("error", "No Products in Cart");
			return "redirect:/";
		}

		try {
			double roundedTotal = cartTotal(items);

			RazorpayClient razorpay = new RazorpayClient(razorpayKeyId, razorpayKeySecret);

			JSONObject orderRequest = new JSONObject();
			// Math.round avoids floating-point truncation (e.g. 19.99 * 100 = 1998.99999...)
			orderRequest.put("amount", Math.round(roundedTotal * 100));
			orderRequest.put("currency", "INR");
			orderRequest.put("receipt", "order_" + System.currentTimeMillis());

			com.razorpay.Order order = razorpay.orders.create(orderRequest);

			map.put("razorpayOrderId", order.get("id"));
			map.put("razorpayKeyId", razorpayKeyId);
			map.put("amount", roundedTotal);
			map.put("currency", "INR");
			map.put("userEmail", user.getEmail());
			map.put("userContact", user.getMobile());
			map.put("userName", user.getName());
			map.put("items", items);
			map.put("user", user);
			map.put("total", roundedTotal);

			return "checkout.html";
		} catch (RazorpayException e) {
			session.setAttribute("error", "Payment initialization failed. Please try again.");
			return "redirect:/user/cart";
		}
	}

	@Override
	@Transactional
	public String paymentSuccess(String paymentId, String orderId, String signature, String address,
			Principal principal, HttpSession session, ModelMap map) {
		try {
			String data = orderId + "|" + paymentId;

			if (!Utils.verifySignature(data, signature, razorpayKeySecret)) {
				session.setAttribute("error", "Payment Verification Failed!");
				return "redirect:/user/cart";
			}

			User user = userDao.findByEmail(principal.getName()).orElseThrow();
			List<CartItem> cartItems = itemRepository.findByUser(user);

			if (cartItems.isEmpty()) {
				session.setAttribute("error", "No Products in Cart");
				return "redirect:/";
			}

			Order order = new Order();
			order.setUser(user);
			order.setRazorpayOrderId(orderId);
			order.setRazorpayPaymentId(paymentId);
			order.setRazorpaySignature(signature);
			order.setOrderDate(LocalDateTime.now());
			order.setStatus("PAID");
			order.setDeliveryAddress(address);
			order.setTotalAmount(cartTotal(cartItems));
			orderRepository.save(order);

			List<OrderItem> orderItems = cartItems.stream().map(cartItem -> {
				OrderItem orderItem = new OrderItem();
				orderItem.setOrder(order);
				orderItem.setProduct(cartItem.getProduct());
				orderItem.setQuantity(cartItem.getQuantity());
				orderItem.setPrice(cartItem.getProduct().getPrice());
				return orderItem;
			}).toList();
			orderItemRepository.saveAll(orderItems);

			itemRepository.deleteAll(cartItems);

			// session (not ModelMap) so the message survives the redirect
			session.setAttribute("success", "Order Placed Successfully!");
			return "redirect:/user/orders";
		} catch (RazorpayException e) {
			session.setAttribute("error", "Payment Processing Failed: " + e.getMessage());
			return "redirect:/user/cart";
		}
	}

	@Override
	public String viewOrders(Principal principal, HttpSession session, ModelMap map) {
		if (principal == null)
			return "redirect:/login";

		User user = userDao.findByEmail(principal.getName()).orElseThrow();
		map.put("orders", orderRepository.findByUser(user));
		return "orders.html";
	}
}
