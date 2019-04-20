<%-- <jsp:include page="base.jsp"></jsp:include> --%>
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
	var id = document.getElementsByName('purchase_product_id');
	var idValue;
	for(var i = 0; i < id.length; i++){
	    if(id[i].checked){
	    	idValue = id[i].value;
	    }
	}
	
	//for enquiry [S]
	var enquiryPathWithIdValue = "${pageContext.request.contextPath}/CustomerPurchaseProductController?action=enquiryEnquiry&purchase_product_id="+idValue;
	//for enquiry [E]
	
	if (idValue !=null) {
		//for enquiry [S]
		document.getElementById('enquiryEnquiry').href = enquiryPathWithIdValue;
		//for enquiry [E]
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
					<li class="title"><a href="${pageContext.request.contextPath}/jsp/order/customerPurchaseProduct.jsp">Customer Purchase Product List</a></li>
					<li class="bread"><a href="">Dashboard > Order 
							Management > Customer Purchase List > Customer Purchase Product List</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	<table class="display" style="width: 100%" cellspacing="10">			
		<tr>
			<td Class ="FormCellColor">Purchase ID</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${purchase_id}" /></td>
			<td Class ="FormCellColor">Requisition ID</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${requisition_id}" /></td>
			<td Class ="FormCellColor">DateTime</td>
			<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${date_time}" /></td> --%>
			<td Class ="FormInputColor" colspan="2">
				<fmt:parseDate pattern="yyyyMMddHHmmss" value="${date_time}" var="parsedDate" />
				<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
			</td>
			<td Class ="FormCellColor">Customer Name</td>
			<td Class ="FormInputColor" colspan="2"><c:out value="${customer_name}" /></td>
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
				<th Class ="HeaderTH">Sales Product ID</th>
				<th Class ="HeaderTH">Product Requisition ID</th>
				<th Class ="HeaderTH">Requisition ID</th>
				<th Class ="HeaderTH">DateTime</th>
				<!-- <th Class ="HeaderTH">Product ID</th> -->
				<th Class ="HeaderTH">Product Name</th>
				<!-- <th Class ="HeaderTH">Pack Type</th>
				<th Class ="HeaderTH">Pack Size</th>
				<th Class ="HeaderTH">Pieces</th>
				<th Class ="HeaderTH">Bonus ID</th>
				<th Class ="HeaderTH">Bonus Name</th> -->
				<!-- <th Class ="HeaderTH">Order Pack</th> -->
				<th Class ="HeaderTH">Order Quantity</th>
				<th Class ="HeaderTH">MRP</th>
				<th Class ="HeaderTH">Total MRP</th>
				<th Class ="HeaderTH">Discount Amount</th>
				<th Class ="HeaderTH">Total Amount</th>
				<th Class ="HeaderTH">Order Status</th>
				<th Class ="HeaderTH">Delivery Status</th>
			</tr>
		</thead>
		
		<tbody>
			<c:forEach items="${customerPurchaseProducts}" var="cpp"> 
				<tr>
					<td Class ="FormInputColor"><input type="radio" name="purchase_product_id" id="purchase_product_id" value="${cpp.purchase_product_id}" onclick="javascript: getRadioValue();" /></td>
					<td Class ="FormInputColor"><c:out value="${cpp.purchase_product_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpp.requisition_product_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpp.requisition_id}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cpp.date_time}" /></td> --%>
					<td Class ="FormInputColor">
						<fmt:parseDate pattern="yyyyMMddHHmmss" value="${cpp.date_time}" var="parsedDate" />
						<fmt:formatDate value="${parsedDate}" pattern="dd-MM-yyyy HH:mm:ss" />
					</td>
					<%-- <td Class ="FormInputColor"><c:out value="${cpp.product_id}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cpp.product_name}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cpp.pack_type}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpp.pack_size}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpp.piceces}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpp.bonus_id}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpp.bonus_name}" /></td> --%>
					<%-- <td Class ="FormInputColor"><c:out value="${cpp.order_pack}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cpp.order_quantity}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpp.mrp_price}" /> <br>Unit Price</td>
					<td Class ="FormInputColor"><c:out value="${cpp.total_mrp_price}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpp.discount_amt}" /></td>
					<td Class ="FormInputColor"><c:out value="${cpp.total_amount}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cpp.order_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cpp.order_status == 'P' ? 'Pending' : cpp.order_status == 'A' ? 'Approved' : cpp.order_status == 'C' ? 'Cancel' : cpp.order_status == 'S' ? 'Success' : ''}" /></td>
					<%-- <td Class ="FormInputColor"><c:out value="${cpp.delivery_status}" /></td> --%>
					<td Class ="FormInputColor"><c:out value="${cpp.delivery_status == 'P' ? 'Pending' : cpp.delivery_status == 'D' ? 'Delivered' : cpp.delivery_status == 'C' ? 'Cancel' : cpp.delivery_status == 'S' ? 'Success' : ''}" /></td>
				</tr>
			</c:forEach>
		</tbody>
	</table>
	<!-- for get Data from sales [S] -->
	<input type="hidden" name="purchase_id" id="purchase_id" value="${purchase_id}">
	<input type="hidden" name="requisition_id" id="requisition_id" value="${requisition_id}">
	<input type="hidden" name="date_time" id="date_time" value="${date_time}">
	<input type="hidden" name="customer_name" id="customer_name" value="${customer_name}">
	<input type="hidden" name="mobile" id="mobile" value="${mobile}">
	<%
	String purchase_id = (String)request.getAttribute("purchase_id");
	String requisition_id = (String)request.getAttribute("requisition_id");
	String date_time = (String)request.getAttribute("date_time");
	String customer_name = (String)request.getAttribute("customer_name");
	String mobile = (String)request.getAttribute("mobile");
	
	HttpSession session1 = request.getSession();
	session1.setAttribute("purchase_id", purchase_id);
	session1.setAttribute("requisition_id", requisition_id);
	session1.setAttribute("date_time", date_time);
	session1.setAttribute("customer_name", customer_name);
	session1.setAttribute("mobile", mobile);
	%>
	<!-- for get Data from sales [E] -->
	<br>
<input type="hidden" name="val" id="val" value="" />
	<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399>
					<br>
					<a id="enquiryEnquiry" Class ="button" href="" onclick="javascript: getRadioValue();">enquiry</a>
					<%-- <a Class ="button" href="${pageContext.request.contextPath}/CustomerPurchaseMainController?action=customerPurchaseMainList">Return</a></td> --%>
					<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/customerPurchaseMain.jsp">Return</a></td>
				</tr>
	</table>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->
	
</body>
</html>