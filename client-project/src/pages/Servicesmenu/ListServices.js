import React from 'react'
import { Space, Table } from 'antd';
import { AndroidOutlined, CaretDownFilled, ChromeOutlined } from '@ant-design/icons';
const { Column } = Table;


const data = [
  {
    id: '1',
    product: 'Computador',
    count: 32,
    state: 'Nuevo',
  },
  {
    id: '2',
    product: 'Celular',
    count: 42,
    state: 'Usado',
  },
  {
    id: '3',
    product: 'Televisor',
    count: 32,
    state: 'Nuevo',
  },
  {
    id: '3',
    product: 'Televisor',
    count: 32,
    state: 'Nuevo',
  },
  {
    id: '3',
    product: 'Televisor',
    count: 32,
    state: 'Nuevo',
  },
  {
    id: '2',
    product: 'Celular',
    count: 42,
    state: 'Usado',
  },
  {
    id: '2',
    product: 'Celular',
    count: 42,
    state: 'Usado',
  }
];
const pagination = {
    pageSize: 5,
    total: data.length
} 

export const ListServices = () => {
  return (
    <Table dataSource={data} pagination={pagination}>
    <Column title="Id" dataIndex="id" key="id"/>
    <Column title="Product" dataIndex="product" key="product" />
    <Column title="Count" dataIndex="count" key="count" />
    <Column title="State" dataIndex="state" key="state"/>
    <Column
      title="Action"
      key="action"
      render={(_, record) => (
        <Space size="middle">
          <a><AndroidOutlined /></a>
          <a><CaretDownFilled /></a>
          <a><ChromeOutlined /></a>
        </Space>
      )}
    />
    </Table>

  )
}

