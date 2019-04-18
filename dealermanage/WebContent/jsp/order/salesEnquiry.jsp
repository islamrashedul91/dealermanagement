<jsp:include page="../../base.jsp"></jsp:include>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%>
<!DOCTYPE html>
<html>
<head>
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

		<div class="mcontent">
			<div class="titlenav">
				<ul>
					<li class="title"><a href="">Sales Enquiry</a></li>
					<li class="bread"><a href="">Dashboard > Order
							Management > Sales List > Sales Enquiry</a></li>
				</ul>
			</div>
			<br>
<div class="card">
	
	<form action="" method="post">
		<table id="example" class="display" style="width: 100%" cellspacing="10">			
			<tr>
				<td Class ="FormCellColor" colspan="2">Sales ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.sales_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Sales Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.sales_type}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Requisition ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.requisition_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Customer ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.customer_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Customer Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.customer_name}" /></td>
				<td Class ="FormCellColor" colspan="2">Mobile</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.mobile}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Product ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.product_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Product Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.product_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Pack Type</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.pack_type}" /></td>			
				<td Class ="FormCellColor" colspan="2">Pack Size</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.pack_size}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Pieces</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.piceces}" /></td>
				<td Class ="FormCellColor" colspan="2"></td>
				<td Class ="FormInputColor" colspan="2"></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Bonus ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.bonus_id}" /></td>			
				<td Class ="FormCellColor" colspan="2">Bonus Name</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.bonus_name}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Pack</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.order_pack}" /></td>
				<td Class ="FormCellColor" colspan="2">Order Quantity</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.order_quantity}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">MRP BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.mrp_price}" /></td>
				<td Class ="FormCellColor" colspan="2">Total MRP BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.total_mrp_price}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Discount Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.discount_amt}" /></td>
				<td Class ="FormCellColor" colspan="2">Total Amount BDT.</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.total_amount}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Needed Date</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.needed_date_time}" /></td>			
				<td Class ="FormCellColor" colspan="2">From Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.from_account_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">To Account</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.to_account_id}" /></td>
				<td Class ="FormCellColor" colspan="2">Salesman ID</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.salesman_id}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Order Status</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${sales.order_status}" /></td> --%>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.order_status == 'P' ? 'Pending' : sales.order_status == 'A' ? 'Approved' : sales.order_status == 'C' ? 'Cancel' : sales.order_status == 'S' ? 'Success' : ''}" /></td>
				<td Class ="FormCellColor" colspan="2">Delivery Status</td>
				<%-- <td Class ="FormInputColor" colspan="2"><c:out value="${sales.delivery_status}" /></td> --%>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.delivery_status == 'P' ? 'Pending' : sales.delivery_status == 'D' ? 'Delivered' : sales.delivery_status == 'C' ? 'Cancel' : sales.delivery_status == 'S' ? 'Success' : sales.delivery_status == 'R' ? 'Return' : ''}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.created}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.updated}" /></td>
			</tr>
			
			<tr>
				<td Class ="FormCellColor" colspan="2">Created By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.created_by}" /></td>
				<td Class ="FormCellColor" colspan="2">Updated By</td>
				<td Class ="FormInputColor" colspan="2"><c:out value="${sales.updated_by}" /></td>
			</tr>
		</table>
		<br>
		
		<table align="center" width="100%">
			
				<tr>
					<td><hr align=left width="100%" color=#003399><br>
						<a Class ="button" href="${pageContext.request.contextPath}/jsp/order/sales.jsp">Return</a>
					</td>
				</tr>
		</table>
	</form>
	</div>
</div><!-- mcontent -->
	
</div><!-- main -->

	<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

</body>
</html>