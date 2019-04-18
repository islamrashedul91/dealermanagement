package com.rashed.pharmacy.controller;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.zxing.WriterException;

import com.rashed.pharmacy.model.TransactionMain;
import com.rashed.pharmacy.dao.TransactionMainDAO;
import com.rashed.pharmacy.dao.TransactionProductDAO;
import com.rashed.pharmacy.util.*;

public class TransactionMainController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String LIST_TRANSACTIONMAIN = "/jsp/order/transactionMainList.jsp";
	private static String ENQUIRY = "/jsp/order/transactionMainEnquiry.jsp";
	
	private static String LIST_TRANSACTIONPRODUCT = "/jsp/order/transactionProductList.jsp";
	private static String LIST_TRANSACTIONPRODUCTENQUIRY = "/jsp/order/transactionProductListEnquiry.jsp";
	
	private TransactionMainDAO tmdao;
	private TransactionProductDAO tpdao;
	
	String action = "";
	String message = "";
	
       
    public TransactionMainController() {
        super();
        
        tmdao = new TransactionMainDAO();
        tpdao = new TransactionProductDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String transaction_id = request.getParameter("transaction_id");
			String strOrderStatus = tmdao.getSelectedOtherID(transaction_id).getOrder_status();
			String date_time = tmdao.getSelectedOtherID(transaction_id).getDate_time();
			
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("S")) {
				tmdao.delete(transaction_id);
				message = "Transaction " + transaction_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
					message = "Approved Transaction can not be deleted !!!";
					request.setAttribute("success", message);
			}
			forward=LIST_TRANSACTIONMAIN;
			request.setAttribute("transactionMains", tmdao.getAllTransactionMain());
		} else if(action.equalsIgnoreCase("transactionMainList")){
			forward = LIST_TRANSACTIONMAIN;
			request.setAttribute("transactionMains", tmdao.getAllTransactionMain());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String transaction_id = request.getParameter("transaction_id");
			TransactionMain tm = tmdao.getTransactionMainById(transaction_id);
			request.setAttribute("transactionMain", tm);
		} else if(action.equalsIgnoreCase("return")){
			forward = LIST_TRANSACTIONPRODUCT;
			
			String transaction_id = request.getParameter("transaction_id");
			String purchase_id = request.getParameter("purchase_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("transactionProducts", tpdao.getAllTransactionProductByMainIdDateTime(transaction_id, purchase_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("transaction_id", transaction_id);
			request.setAttribute("purchase_id", purchase_id);
			request.setAttribute("strDateTime", date_time);
			request.setAttribute("owner_name", request.getParameter("owner_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			//request.setAttribute("sumTotalAmount", spdao.sumTotalAmount(purchase_id, requisition_id, date_time).getTotal_amount());
			request.setAttribute("sumTotalAmount", tpdao.sumTotalAmount(transaction_id, purchase_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else if(action.equalsIgnoreCase("transactionProductListEnquiry")){
			forward = LIST_TRANSACTIONPRODUCTENQUIRY;
			
			String transaction_id = request.getParameter("transaction_id");
			String purchase_id = request.getParameter("purchase_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("transactionProducts", tpdao.getAllTransactionProductByMainIdDateTime(transaction_id, purchase_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("transaction_id", transaction_id);
			request.setAttribute("purchase_id", purchase_id);
			request.setAttribute("date_time", date_time);
			request.setAttribute("owner_name", request.getParameter("owner_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", tpdao.sumTotalAmount(transaction_id, purchase_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

}
