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

import com.rashed.pharmacy.dao.AccountDAO;
import com.rashed.pharmacy.dao.CompanyDAO;
import com.rashed.pharmacy.dao.DayWiseAccountBalanceDAO;
import com.rashed.pharmacy.dao.ProfitLossDAO;
import com.rashed.pharmacy.dao.OwnerInfoDAO;

import com.rashed.pharmacy.model.ExpenseMain;
import com.rashed.pharmacy.dao.ExpenseMainDAO;
import com.rashed.pharmacy.dao.ExpenseProductDAO;
import com.rashed.pharmacy.util.*;

public class ExpenseMainController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String INSERT_OR_EDIT = "/jsp/expense/expenseMainAdd.jsp";
	private static String LIST_EXPENSEMAIN = "/jsp/expense/expenseMainList.jsp";
	private static String ENQUIRY = "/jsp/expense/expenseMainEnquiry.jsp";
	
	private static String LIST_EXPENSEPRODUCT = "/jsp/expense/expenseProductList.jsp";
	private static String LIST_EXPENSEPRODUCTENQUIRY = "/jsp/expense/expenseProductListEnquiry.jsp";
	
	private AccountDAO adao;
	private DayWiseAccountBalanceDAO dwabdao;
	//private ProfitLossDAO pldao;
	private CompanyDAO comdao;
	private OwnerInfoDAO odao;
	private ExpenseMainDAO emdao;
	private ExpenseProductDAO epdao;
	
	String action = "";
	String message = "";
	
       
    public ExpenseMainController() {
        super();
        adao = new AccountDAO();
        dwabdao = new DayWiseAccountBalanceDAO();
        //pldao = new ProfitLossDAO();
        comdao = new CompanyDAO();
        odao = new OwnerInfoDAO();
        emdao = new ExpenseMainDAO();
        epdao = new ExpenseProductDAO();
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String forward="";
		action = request.getParameter("action");
		// for set the action in session [S]
		HttpSession session = request.getSession();
		session.setAttribute("action", action);
		// for set the action in session [E]
		
		if(action.equalsIgnoreCase("delete")){
			String expense_id = request.getParameter("expense_id");
			String strOrderStatus = emdao.getSelectedOtherID(expense_id).getOrder_status();
			String date_time = emdao.getSelectedOtherID(expense_id).getDate_time();
			
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("S")) {
				emdao.delete(expense_id);
				message = "Expense " + expense_id + " deleted Successfully!!!";
				request.setAttribute("success", message);
			} else {
					message = "Approved Expense can not be deleted !!!";
					request.setAttribute("success", message);
			}
			forward=LIST_EXPENSEMAIN;
			request.setAttribute("expenseMains", emdao.getAllExpenseMain());
			/*message = "Data Deleted Successfully!!!";
			request.setAttribute("success", message);*/
		} else if(action.equalsIgnoreCase("cancel")){
			String expense_id = request.getParameter("expense_id");
			String strOrderStatus = emdao.getSelectedOtherID(expense_id).getOrder_status();
			
			if (!strOrderStatus.equals("A")) {
				emdao.cancel(expense_id);
				
				message = "Expense " + expense_id + " Cancelled Successfully!!!";
				request.setAttribute("success", message);
			} else {
				message = "Approved Expense can not be cancelled !!!";
				request.setAttribute("success", message);
			}
			
			forward=LIST_EXPENSEMAIN;
			request.setAttribute("expenseMains", emdao.getAllExpenseMain());
		} else if(action.equalsIgnoreCase("approve")){
			String expense_id = request.getParameter("expense_id");
			String date_time = emdao.getSelectedOtherID(expense_id).getDate_time();
			String strOrderStatus = emdao.getSelectedOtherID(expense_id).getOrder_status();
			
			if (!strOrderStatus.equals("A") && !strOrderStatus.equals("C")) {
				emdao.approve(expense_id);
				
				epdao.approveByMainExpense(expense_id, date_time);
				
				message = "Expense" + expense_id + " Approved Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Expense can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A")) {
					message = "Already Approved !!!";
					request.setAttribute("success", message);
				}
			}
			
			forward=LIST_EXPENSEMAIN;
			request.setAttribute("expenseMains", emdao.getAllExpenseMain());
		} else if(action.equalsIgnoreCase("expenseApprove")){
			String expense_id = request.getParameter("expense_id");
			String strExpenseType = emdao.getSelectedOtherID(expense_id).getExpense_type();
			String strOrderStatus = emdao.getSelectedOtherID(expense_id).getOrder_status();
			String strExpenseStatus = emdao.getSelectedOtherID(expense_id).getExpense_status();
			String date_time = emdao.getSelectedOtherID(expense_id).getDate_time();
			String strFromAccount = emdao.getSelectedOtherID(expense_id).getFrom_account_id();
			String strToAccount = emdao.getSelectedOtherID(expense_id).getTo_account_id();
			double doubleTotalAmount = emdao.getSelectedOtherID(expense_id).getTotal_amount();

			if (strOrderStatus.equals("A") && !strExpenseStatus.equals("A") && !strExpenseStatus.equals("C")) {
				emdao.expenseApprove(expense_id);
				
				epdao.expenseApproveByMainExpense(expense_id, date_time);
				
				// for insert data into account table [S]
				//adao.balanceUpdate(strFromAccount, doubleTotalAmount);
				SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
				Date date = new Date();  
				String strCurrentDateTime = formatter.format(date);
				adao.purchaseBalanceUpdate(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				// for insert data into account table [E]
				
				// for insert data into day_wise_account_balance table [S]
				dwabdao.purchaseDayBalance(strFromAccount, doubleTotalAmount, strCurrentDateTime);
				// for insert data into day_wise_account_balance table [E]
				
				message = "Expense " + expense_id + " Approve Successfully!!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Cancelled Expense can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("P")) {
					message = "Without Approve Expense can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strExpenseStatus.equals("C")) {
					message = "Cancelled Expense can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strExpenseStatus.equals("A")) {
					message = "Already Approved !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_EXPENSEMAIN;
			request.setAttribute("expenseMains", emdao.getAllExpenseMain());
		} else if(action.equalsIgnoreCase("expenseCancel")){
			String expense_id = request.getParameter("expense_id");
			String strExpenseType = emdao.getSelectedOtherID(expense_id).getExpense_type();
			String strOrderStatus = emdao.getSelectedOtherID(expense_id).getOrder_status();
			String strExpenseStatus = emdao.getSelectedOtherID(expense_id).getExpense_status();
			String date_time = emdao.getSelectedOtherID(expense_id).getDate_time();
			String strFromAccount = emdao.getSelectedOtherID(expense_id).getFrom_account_id();
			String strToAccount = emdao.getSelectedOtherID(expense_id).getTo_account_id();
			double doubleTotalAmount = emdao.getSelectedOtherID(expense_id).getTotal_amount();
			
			if (strOrderStatus.equals("A") && !strExpenseStatus.equals("A") && !strExpenseStatus.equals("C") && !strExpenseStatus.equals("R")) {
				emdao.expenseCancel(expense_id);
				
				epdao.expenseCaneclByMainExpense(expense_id, date_time);
				
				message = "Expense " + expense_id + " Delivery Return !!!";
				request.setAttribute("success", message);
			} else {
				if (strOrderStatus.equals("C")) {
					message = "Expense Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("P")) {
					message = "Without Approve Expense can not be Approved !!!";
					request.setAttribute("success", message);
				} else if (strExpenseStatus.equals("C")) {
					message = "Expense Already Cancelled !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strExpenseStatus.equals("A")) {
					message = "Already Approved !!!";
					request.setAttribute("success", message);
				} else if (strOrderStatus.equals("A") && strExpenseStatus.equals("C")) {
					message = "Already Cancelled !!!";
					request.setAttribute("success", message);
				}
			}
			forward=LIST_EXPENSEMAIN;
			request.setAttribute("expenseMains", emdao.getAllExpenseMain());
		} else if(action.equalsIgnoreCase("edit")){
			forward = INSERT_OR_EDIT;
			String expense_id = request.getParameter("expense_id");
			ExpenseMain em = emdao.getExpenseMainById(expense_id);
			request.setAttribute("expenseMain", em);
			
			// for get all company when add purchase [S]
			request.setAttribute("allCompany", comdao.getAllCompany());
			// for get all company when add purchase [E]
			// for get Owner when add requisition [S]
			request.setAttribute("allOwner", odao.getAllOwnerInfo());
			// for get Owner when add requisition [E]
			
			// selected other respective id during update [S]
			request.setAttribute("selectedOwnerId", emdao.getSelectedOtherID(expense_id).getOwner_id());
			request.setAttribute("selectedCompanyId", emdao.getSelectedOtherID(expense_id).getCompany_id());
			// selected other respective id during update [E]
		} else if(action.equalsIgnoreCase("expenseMainList")){
			forward = LIST_EXPENSEMAIN;
			request.setAttribute("expenseMains", emdao.getAllExpenseMain());
		} else if(action.equalsIgnoreCase("enquiry")){
			forward = ENQUIRY;
			String expense_id = request.getParameter("expense_id");
			ExpenseMain em = emdao.getExpenseMainById(expense_id);
			request.setAttribute("expenseMain", em);
		} else if(action.equalsIgnoreCase("return")){
			forward = LIST_EXPENSEPRODUCT;
			
			String expense_id = request.getParameter("expense_id");
			String expense_type = request.getParameter("expense_type");
			String date_time = request.getParameter("date_time");
			request.setAttribute("expenseProducts", epdao.getAllExpenseProductByMainIdDateTime(expense_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("expense_id", expense_id);
			request.setAttribute("expense_type", expense_type);
			request.setAttribute("strDateTime", date_time);
			request.setAttribute("owner_name", request.getParameter("owner_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", epdao.sumTotalAmount(expense_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else if(action.equalsIgnoreCase("expenseProductListEnquiry")){
			forward = LIST_EXPENSEPRODUCTENQUIRY;
			
			String expense_id = request.getParameter("expense_id");
			String date_time = request.getParameter("date_time");
			request.setAttribute("expenseProducts", epdao.getAllExpenseProductByMainIdDateTime(expense_id, date_time));
			// for transfer data into another page (Product Requisition) [S]
			request.setAttribute("expense_id", expense_id);
			request.setAttribute("date_time", date_time);
			request.setAttribute("owner_name", request.getParameter("owner_name"));
			request.setAttribute("mobile", request.getParameter("mobile"));
			// for transfer data into another page (Product Requisition) [E]
			// for Requisition Product sum total amount [S]
			request.setAttribute("sumTotalAmount", epdao.sumTotalAmount(expense_id, date_time).getTotal_amount());
			// for Requisition Product sum total amount [E]
		} else {
			forward = INSERT_OR_EDIT;
			// generated auto increment id during add [S]
			request.setAttribute("expenseId", emdao.getExpenseMainID().getExpense_id());
			// generated auto increment id during add [E]
			
			// for get all company when add expense [S]
			request.setAttribute("allCompany", comdao.getAllCompany());
			// for get all company when add expense [E]
			// for get Owner when add expense [S]
			request.setAttribute("allOwner", odao.getAllOwnerInfo());
			// for get Owner when add expense [E]
			
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(forward);
		rd.forward(request, response);
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("======action======="+ action);
		
		ExpenseMain em = new ExpenseMain();
		
		em.setExpense_id(request.getParameter("expense_id"));
		em.setExpense_type(request.getParameter("expense_type"));
		em.setDate_time(request.getParameter("date_time"));
		em.setOwner_id(request.getParameter("owner_id"));
		em.setOwner_name(request.getParameter("owner_name"));
		em.setMobile(request.getParameter("mobile"));
		em.setNeeded_date_time(request.getParameter("needed_date_time"));
		em.setFrom_account_id(request.getParameter("from_account_id"));
		em.setTo_account_id(request.getParameter("to_account_id"));
		em.setCompany_id(request.getParameter("company_id"));
		em.setCompany_name(request.getParameter("company_name"));
		em.setTotal_amount(Double.parseDouble(request.getParameter("total_amount")));
		em.setOrder_status(request.getParameter("order_status"));
		em.setExpense_status(request.getParameter("expense_status"));
		em.setCreated(request.getParameter("created"));
		em.setUpdated(request.getParameter("updated"));
		em.setCreated_by(request.getParameter("created_by"));
		em.setUpdated_by(request.getParameter("updated_by"));
	
		String expense_id = request.getParameter("expense_id");
		String expense_type = request.getParameter("expense_type");
		String strDateTime = request.getParameter("date_time");

		if(action.equalsIgnoreCase("save")){
			emdao.save(em);
		} else if(action.equalsIgnoreCase("edit")){
			em.setExpense_id(expense_id);
			emdao.update(em);
		}
		
		RequestDispatcher rd = request.getRequestDispatcher(LIST_EXPENSEPRODUCT);
		request.setAttribute("expenseProducts", epdao.getAllExpenseProductByMainIdDateTime(expense_id, strDateTime));

		if(action.equalsIgnoreCase("save")){
			message = "Data Inserted Successfully!!!";
			request.setAttribute("success", message);
		} else if(action.equalsIgnoreCase("edit")){
			message = "Successfully Data Updated!!!";
			request.setAttribute("success", message);
		}
		// for transfer data into another page (Product Requisition) [S]
		request.setAttribute("expense_id", expense_id);
		request.setAttribute("expense_type", expense_type);
		request.setAttribute("strDateTime", strDateTime);
		request.setAttribute("owner_name", request.getParameter("owner_name"));
		request.setAttribute("mobile", request.getParameter("mobile"));
		// for transfer data into another page (Product Requisition) [E]
		// for Requisition Product sum total amount [S]
		request.setAttribute("sumTotalAmount", epdao.sumTotalAmount(expense_id, strDateTime).getTotal_amount());
		// for Requisition Product sum total amount [E]
		
		rd.forward(request, response);
	}

}
