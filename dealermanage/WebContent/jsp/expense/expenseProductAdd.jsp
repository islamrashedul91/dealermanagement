<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Online Pharmacy</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script language="JavaScript">

function expenseCategoryChng() {
	oSelectOne = frmSave.elements["category_id"];
	index = oSelectOne.selectedIndex;
	var selected_option_text = oSelectOne.options[index].text;
	
	var split_selected_option_text = selected_option_text.split(' - ');
	var finalTextName = split_selected_option_text[0];
	
	document.getElementById('category_name').value = finalTextName;

}

function quantityToTotalPrice() {
	
	var quantity = document.getElementById('quantity').value;
	var price = document.getElementById('price').value;
	var quantityMultiplyPrice = quantity * price;
	
	document.getElementById('total_price').value = quantityMultiplyPrice.toFixed(2);

}

function discountToTotalAmount() {
	
	var discount = document.getElementById('discount_amt').value;
	var totalPrice = document.getElementById('total_price').value;
	var totalPriceMinusDiscount = totalPrice - discount;
	
	document.getElementById('total_amount').value = totalPriceMinusDiscount.toFixed(2);

}

</script>

</head>
<body>
<%
String action = (String) session.getAttribute("action");
System.out.println("++++++"+action);
%>
<div class="mcontent">
			<div class="titlenav">
				<ul>					
					<li class="title"><a href="">
					<%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Expense Product Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Expense Product Update</td>
					<%
					}
					%>
					</a></li>
					<li class="bread"><a href="">Dashboard > Expense Management > Expense Product List > <%
					if (action.equalsIgnoreCase("save")) {
					%>
						<td class="PageHeader">Expense Product Add</td>
					<%
					} else if (action.equalsIgnoreCase("edit")) {
					%>
						<td class="PageHeader">Expense Product Update</td>
					<%
					}
					%></a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table class="display" style="width: 100%" cellspacing="10">			
		<tr>
			<td Class ="FormCellColor">Expense ID</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${expense_id}" /></td>
			<td Class ="FormCellColor">DateTime</td>
			<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${strDateTime}" /></td> --%>
			<td Class ="FormInputColor" colspan="2">
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${strDateTime}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
			</td>
			<td Class ="FormCellColor">Owner Name</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${owner_name}" /></td>
			<td Class ="FormCellColor">Mobile</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${mobile}" /></td>
		</tr>
	</table>
</div>
<br>
		<div class="card">
			<div class="form-style-2">
<%
//SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
Date date = new Date();  
String strDate = formatter.format(date);
%>	

	<form action="ExpenseProductController" method="post" name="frmSave">
		<div class="form-style-2-heading">Provide your information </div>
			<div class="square-44">
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field1"><span>Expense Product ID <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field-60" readonly="readonly" name="expense_product_id" id="expense_product_id" value="${expenseProductId}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field1"><span>Expense Product ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="expense_product_id" id="expense_product_id" value="${expenseProduct.expense_product_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field2"><span>Expense ID <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field-60" readonly="readonly" name="expense_id" id="expense_id" value="${expense_id}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field2"><span>Expense ID <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="expense_id" id="expense_id" value="${expenseProduct.expense_id}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field3"><span>Expense Type <span class="required">*</span></span>
				<!-- generated auto increment id during add [S] -->
				<input type="text" class="input-field-60" readonly="readonly" name="expense_type" id="expense_type" value="${expense_type}"  maxlength=25 size=40 required />
				<!-- generated auto increment id during add [E] --> 
			</label> 
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field3"><span>Expense Type <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="expense_type" id="expense_type" value="${expenseProduct.expense_type}"  maxlength=25 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field4"><span>DateTime <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${strDateTime}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="date_time" id="date_time" value="${strDateTime}"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field4"><span>DateTime <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseProduct.date_time}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="date_time" id="date_time" value="${expenseProduct.date_time}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field5"><span>Expense Category ID </span>
				<select name="category_id" id="category_id" class="select-field-60" onchange="expenseCategoryChng();" >
					<option value="" >Select one</option>
					<c:forEach items="${allCategory}" var="ac">
						<option value="${ac.category_id}">${ac.category_name} - ${ac.category_id}</option>
					</c:forEach>
				</select> 
			</label>
			
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field5"><span>Expense Category ID </span>
				<select name="category_id" id="category_id" class="select-field-60" onchange="expenseCategoryChng();" >
					<c:forEach items="${allCategory}" var="ac">
						<option value="${ac.category_id}" ${ac.category_id == selectedCategoryId ? 'selected="selected"' : ''}>${ac.category_name} - ${ac.category_id}</option>
					</c:forEach>
				</select>
			</label>
			<%
			}
			%>
			
			<label for="field6"><span>Expense Category Name <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="category_name" id="category_name" value="${expenseProduct.category_name}"  maxlength=40 size=40 required /> 
			</label>
			
			<label for="field7"><span>Quantity <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="quantity" id="quantity" value="${expenseProduct.quantity}" onchange="quantityToTotalPrice(); discountToTotalAmount();" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field8"><span>Price <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="price" id="price" value="${expenseProduct.price}" onchange="quantityToTotalPrice(); discountToTotalAmount();" maxlength=10 size=40 required /> 
			</label>
			
			</div>
			
			&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
			
			<div class="square-44">
			
			<label for="field9"><span>Total Price <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_price" id="total_price" value="${expenseProduct.total_price}"  maxlength=10 size=40 required /> 
			</label>
			
			<label for="field10"><span>Discount Amount <span class="required">*</span></span>
				<input type="text" class="input-field-60" name="discount_amt" id="discount_amt" value="${expenseProduct.discount_amt}" onchange="discountToTotalAmount();" maxlength=10 size=40 required /> 
			</label>
			
			<label for="field11"><span>Total Amount BDT. <span class="required">*</span></span>
				<input type="text" class="input-field-60" readonly="readonly" name="total_amount" id="total_amount" value="${expenseProduct.total_amount}"  maxlength=10 size=40 required /> 
			</label>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field12"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="P">Pending</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field12"><span>Order Status </span>
				<select name="order_status" id="order_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${expenseProduct.order_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="A" ${expenseProduct.order_status == 'A' ? 'selected="selected"' : ''}>Approved</option>
					<option value="C" ${expenseProduct.order_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
					<option value="S" ${expenseProduct.order_status == 'S' ? 'selected="selected"' : ''}>Success</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field13"><span>Expense Status </span>
				<select name="expense_status" id="expense_status" class="select-field-60" >
					<option value="P">Pending</option>
				</select> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field13"><span>Expense Status </span>
				<select name="expense_status" id="expense_status" class="select-field-60" >
					<option value="" >Select one</option>
					<option value="P" ${expenseProduct.expense_status == 'P' ? 'selected="selected"' : ''}>Pending</option>
					<option value="A" ${expenseProduct.expense_status == 'A' ? 'selected="selected"' : ''}>Approved</option>
					<option value="S" ${expenseProduct.expense_status == 'S' ? 'selected="selected"' : ''}>Success</option>
					<option value="C" ${expenseProduct.expense_status == 'C' ? 'selected="selected"' : ''}>Cancel</option>
					<option value="R" ${expenseProduct.expense_status == 'R' ? 'selected="selected"' : ''}>Return</option>
				</select> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field14"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field14"><span>Created <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseProduct.created}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="created" id="created" value="${expenseProduct.created}"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<%
			if (action.equalsIgnoreCase("save")) {
			%>
			<label for="field15"><span>Updated </span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${expenseProduct.updated}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="${expenseProduct.updated}"  maxlength=14 size=40 /> 
			</label>
			<%
			} else if (action.equalsIgnoreCase("edit")) {
			%>
			<label for="field15"><span>Updated <span class="required">*</span></span>
				<!-- just display fancy date only [S]-->
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="<%=strDate%>" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" var="fmtDate" />
				<input type="text" class="input-field-60" readonly="readonly" value="${fmtDate}" size=40/>
				<!-- just display fancy date only [E]-->
				<input type="hidden" class="input-field-60" readonly="readonly" name="updated" id="updated" value="<%=strDate%>"  maxlength=14 size=40 required /> 
			</label>
			<%
			}
			%>
			
			<label for="field16"><span>Created By </span>
				<input type="text" class="input-field-60" name="created_by" id="created_by" value="${expenseProduct.created_by}"  maxlength=40 size=40 /> 
			</label>
			
			</div>
			
			<div class="square-44">
			
			<label for="field17"><span>Updated By </span>
				<input type="text" class="input-field-60" name="updated_by" id="updated_by" value="${expenseProduct.updated_by}"  maxlength=40 size=40 /> 
			</label>
			
			</div>
			<br><br>
			<label><span></span>
					<input type="submit" value="Submit" />
					<a Class ="button" href="${pageContext.request.contextPath}/ExpenseMainController?action=return&expense_id=${expense_id}&expense_type=${expense_type}&date_time=${strDateTime}&owner_name=${owner_name}&mobile=${mobile}">Return</a></td>
			</label>
			
	</form>
	</div>
		</div>	
	</div><!-- mcontent -->
	
</div><!-- main -->
</body>
</html>
<br>
<div>