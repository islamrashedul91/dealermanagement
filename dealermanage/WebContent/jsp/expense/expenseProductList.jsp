<jsp:include page="../../base.jsp"></jsp:include>
<br>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<!-- <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1"> -->
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/copytest.css" />
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/table.css" />

<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/jquery.min.js"></script>
<script type="text/javascript"
	src="${pageContext.request.contextPath}/js/dataTables/jquery.dataTables.min.js"></script>
<link rel="stylesheet"
	href="${pageContext.request.contextPath}/css/jquery.dataTables.min.css">
	
<title>onlinep</title>
<link rel="stylesheet" 	href="${pageContext.request.contextPath}/css/table.css">

<script type="text/javascript">

$(document).ready(function() {
	$('#example').DataTable();
});

function getRadioValue()
{
	var id = document.getElementsByName('expense_product_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for update [S]
	var updatePathWithIdValue = "${pageContext.request.contextPath}/ExpenseProductController?action=edit&expense_product_id="+idValue;
	//for update [E]
	//for delete [S]
	var deletePathWithIdValue = "${pageContext.request.contextPath}/ExpenseProductController?action=delete&expense_product_id="+idValue;
	//for delete [E]
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/ExpenseProductController?action=enquiry&expense_product_id="+idValue;
	//for enquiry [E]
	//for cancel [S]
	var cancelPathWithIdValue = "${pageContext.request.contextPath}/ExpenseProductController?action=cancel&expense_product_id="+idValue;
	//for cancel [E]
	//for approve [S]
	var approvePathWithIdValue = "${pageContext.request.contextPath}/ExpenseProductController?action=approve&expense_product_id="+idValue;
	//for approve [E]
	//for delivery return [S]
	var expenseCancelPathWithIdValue = "${pageContext.request.contextPath}/ExpenseProductController?action=expenseCancel&expense_product_id="+idValue;
	//for delivery return [E]
	
	if (idValue !=null) {
		//for update [S]
		document.getElementById('update').href = updatePathWithIdValue;
		//for update [E]
		//for delete [S]
		document.getElementById('delete').href = deletePathWithIdValue;
		//for delete [E]
		//for enquiry [S]
		document.getElementById('enquiry').href = enquiryPathWithIdValue;
		//for enquiry [E]
		//for cancel [S]
		document.getElementById('cancel').href = cancelPathWithIdValue;
		//for cancel [E]
		//for approve [S]
		document.getElementById('approve').href = approvePathWithIdValue;
		//for approve [E]
		//for delivery return [S]
		document.getElementById('expenseCancel').href = expenseCancelPathWithIdValue;
		//for delivery return [E]
	} else {
		alert("Please select a ID !!");
		return false;
	}
}

</script>
</head>
<body>

<%
String message = (String) request.getAttribute("success");
%>
	<table align="center">
				<%
				if(message!=null) {
				%>
				<tr>
					<th Class="HeaderTH"><%=message %></th>
				</tr>
				<%
				}
				%>
	</table>
	<br>
<div class="mcontent">
			<div class="titlenav">
			<ul>
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/expense/expenseProduct.jsp">Expense Product List</a></li>
					<li class="bread"><a href="">Dashboard > Expense 
							Management > Expense List > Expense Product List</a></li>
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
			<td Class ="FormInputColor">
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${strDateTime}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
			</td>
			<td Class ="FormCellColor">Owner Name</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${owner_name}" /></td>
			<td Class ="FormCellColor">Mobile</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${mobile}" /></td>
			<td Class ="FormCellColor">Total Amount</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${sumTotalAmount}" /></td>
		</tr>
	</table>
</div>
			<br>
<div class="card">
	
	<table id="example" class="display" style="width: 100%; font-size: 13px;">
		<thead>
			<tr>
				<th  Class ="HeaderTH"></th>
				<th Class ="HeaderTH">Expense Product ID</th>
				<th Class ="HeaderTH">DateTime</th>
				<th Class ="HeaderTH">Category Name</th>
				<th Class ="HeaderTH">Quantity</th>
				<th Class ="HeaderTH">Price</th>
				<th Class ="HeaderTH">Total Price</th>
				<th Class ="HeaderTH">Discount Amount</th>
				<th Class ="HeaderTH">Total Amount</th>
				<th Class ="HeaderTH">Order Status</th>
				<th Class ="HeaderTH">Expense Status</th>
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${expenseProducts}" var="ep"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="expense_product_id" id="expense_product_id" value="${ep.expense_product_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${ep.expense_product_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${ep.date_time}" /></td> --%>
					<td Class ="FormInputColor">
						<fmt:parseDate pattern="yyyyMMddHHmmss" value="${ep.date_time}" var="parsedDate" />
						<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
					</td>
					<td Class ="FormInputColor"><c:out value="${ep.category_name}" /></td>
					<td Class ="FormInputColor"><c:out value="${ep.quantity}" /></td>
					<td Class ="FormInputColor"><c:out value="${ep.price}" /> <br>Unit Price</td>
					<td Class ="FormInputColor"><c:out value="${ep.total_price}" /></td>
					<td Class ="FormInputColor"><c:out value="${ep.discount_amt}" /></td>
					<td Class ="FormInputColor"><c:out value="${ep.total_amount}" /></td>
					<td Class ="FormInputColor"><c:out value="${ep.order_status == 'P' ? 'Pending' : ep.order_status == 'A' ? 'Approved' : ep.order_status == 'C' ? 'Cancel' : ep.order_status == 'S' ? 'Success' : ''}" /></td>
					<td Class ="FormInputColor"><c:out value="${ep.expense_status == 'P' ? 'Pending' : ep.expense_status == 'A' ? 'Approved' : ep.expense_status == 'C' ? 'Cancel' : ep.expense_status == 'S' ? 'Success' : ep.expense_status == 'R' ? 'Return' : ''}" /></td>
				</tr>
			</c:forEach>
		</tbody>
	</table>
	<!-- for get Data from Purchase Main [S] -->
	<input type="hidden" name="expense_id" id="expense_id" value="${expense_id}">
	<input type="hidden" name="expense_type" id="expense_type" value="${expense_type}">
	<input type="hidden" name="strDateTime" id="strDateTime" value="${strDateTime}">
	<input type="hidden" name="owner_name" id="owner_name" value="${owner_name}">
	<input type="hidden" name="mobile" id="mobile" value="${mobile}">
	<%
	String expense_id = (String)request.getAttribute("expense_id");
	String expense_type = (String)request.getAttribute("expense_type");
	String strDateTime = (String)request.getAttribute("strDateTime");
	String owner_name = (String)request.getAttribute("owner_name");
	String mobile = (String)request.getAttribute("mobile");
	
	HttpSession session1 = request.getSession();
	session1.setAttribute("expense_id", expense_id);
	session1.setAttribute("expense_type", expense_type);
	session1.setAttribute("strDateTime", strDateTime);
	session1.setAttribute("owner_name", owner_name);
	session1.setAttribute("mobile", mobile);
	%>
	<!-- for get Data from Purchase Main [E] -->
	<br>
<input type="hidden" name="val" id="val" value="" />
	<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399>
					<br>
					<a Class ="button" href="${pageContext.request.contextPath}/ExpenseProductController?action=save">add</a>
					<a id="update" Class ="button" href="" onclick="javascript: getRadioValue();">update</a>
					<a id="approve" Class ="button" href="" onclick="javascript: getRadioValue();">approve</a>
					<a id="cancel" Class ="button" href="" onclick="javascript: getRadioValue();">cancel</a>
					<a id="delete" Class ="button" href="" onclick="javascript: getRadioValue();">delete</a>
					<a id="enquiry" Class ="button" href="" onclick="javascript: getRadioValue();">enquiry</a>
					<a id="expenseCancel" Class ="button" href="" onclick="javascript: getRadioValue();">Expense Cancel</a>
					<%-- <a Class ="button" href="${pageContext.request.contextPath}/ExpenseMainController?action=expenseMainList&expense_id=${expense_id}&owner_name=${owner_name}&mobile=${mobile}">Return</a></td> --%>
					<a Class ="button" href="${pageContext.request.contextPath}/jsp/expense/expenseMain.jsp">Return</a></td>
				</tr>
	</table>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>