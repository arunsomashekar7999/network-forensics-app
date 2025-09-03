import os
import dash
from dash import html, dcc, callback_context
from dash.dependencies import Input, Output, State
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import base64
import io
from datetime import datetime
import json

class WebInterface:
    def __init__(self, traffic_analyzer, incident_detector, data_visualizer):
        self.app = dash.Dash(__name__, 
                           serve_locally=True,
                           meta_tags=[{'name': 'viewport',
                                     'content': 'width=device-width, initial-scale=1.0'}])
        self.app.server.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default-secret-key')
        self.traffic_analyzer = traffic_analyzer
        self.incident_detector = incident_detector
        self.data_visualizer = data_visualizer
        
        # Styling
        self.navbar_style = {
            'backgroundColor': '#2c3e50',
            'padding': '1rem',
            'color': 'white',
            'boxShadow': '0 2px 4px rgba(0,0,0,0.1)',
            'marginBottom': '2rem'
        }
        
        self.card_style = {
            'backgroundColor': 'white',
            'borderRadius': '8px',
            'boxShadow': '0 2px 4px rgba(0,0,0,0.1)',
            'padding': '1.5rem',
            'margin': '1rem'
        }
        
        self.button_style = {
            'backgroundColor': '#2c3e50',
            'color': 'white',
            'border': 'none',
            'padding': '0.5rem 1rem',
            'borderRadius': '4px',
            'cursor': 'pointer'
        }
        
        # Layout
        self.app.layout = html.Div([
            # Navbar
            html.Div(style=self.navbar_style, children=[
                html.H1("Network Forensics Dashboard", style={'margin': '0', 'fontSize': '24px'}),
                html.P("Real-time network analysis and security monitoring",
                      style={'margin': '0.5rem 0 0 0', 'opacity': '0.8'})
            ]),
            
            # Main content
            html.Div(style={'padding': '0 2rem'}, children=[
                # File Upload Section
                html.Div(style=self.card_style, children=[
                    html.H3("Upload Network Capture Files", style={'marginBottom': '1rem'}),
                    dcc.Upload(
                        id='upload-data',
                        children=html.Div([
                            'Drag and Drop or ',
                            html.A('Select Files', style={'color': '#2c3e50', 'textDecoration': 'underline'})
                        ]),
                        style={
                            'width': '100%',
                            'height': '60px',
                            'lineHeight': '60px',
                            'borderWidth': '1px',
                            'borderStyle': 'dashed',
                            'borderRadius': '5px',
                            'textAlign': 'center',
                            'margin': '1rem 0'
                        },
                        multiple=True
                    ),
                    html.Div(id='upload-output'),
                ]),
                
                # Interval for real-time updates
                dcc.Interval(id='interval-component', interval=5000, n_intervals=0),
                
                # Tabs for different views
                dcc.Tabs(id='tabs', value='live-tab', children=[
                    dcc.Tab(label='Live Traffic', value='live-tab'),
                    dcc.Tab(label='File Analysis', value='file-tab'),
                ], style={'marginTop': '1rem'}),
                
                # Tab content
                html.Div(id='tab-content'),
                
                # Traffic Statistics
                html.Div(style=self.card_style, children=[
                    html.H3("Traffic Statistics", className='card-title'),
                    html.Div(id='stats-container', className='stats-grid')
                ]),
                
                # Graphs Container
                html.Div(style={'display': 'flex', 'flexWrap': 'wrap', 'gap': '1rem'}, children=[
                    html.Div(style={'flex': '1', 'minWidth': '400px'}, children=[
                        html.Div(style=self.card_style, children=[
                            html.H3("Traffic Volume"),
                            dcc.Graph(id='traffic-volume-graph')
                        ])
                    ]),
                    html.Div(style={'flex': '1', 'minWidth': '400px'}, children=[
                        html.Div(style=self.card_style, children=[
                            html.H3("Protocol Distribution"),
                            dcc.Graph(id='protocol-dist-graph')
                        ])
                    ])
                ]),
                
                # HTTP/HTTPS Analysis
                html.Div(style=self.card_style, children=[
                    html.H3("HTTP/HTTPS Analysis"),
                    html.Div(id='http-analysis')
                ]),
                
                # Security Incidents
                html.Div(style=self.card_style, children=[
                    html.H3("Security Incidents"),
                    html.Div(id='incidents-table')
                ])
            ])
        ], style={
            'backgroundColor': '#f5f6fa',
            'fontFamily': 'Helvetica, Arial, sans-serif',
            'minHeight': '100vh'
        })
        
        self.setup_callbacks()
    
    def parse_pcap_contents(self, contents, filename):
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        try:
            if 'pcap' in filename:
                # Process PCAP file
                return f"Processing PCAP file: {filename}"
            elif 'log' in filename:
                # Process log file
                return f"Processing log file: {filename}"
        except Exception as e:
            return f"Error processing file: {str(e)}"
    
    def setup_callbacks(self):
        @self.app.callback(
            Output('upload-output', 'children'),
            Input('upload-data', 'contents'),
            State('upload-data', 'filename')
        )
        def update_output(list_of_contents, list_of_names):
            if list_of_contents is not None:
                return [
                    html.Div([
                        html.H5(f"Processing {name}..."),
                        html.P(self.parse_pcap_contents(c, n))
                    ]) for c, n in zip(list_of_contents, list_of_names)
                ]
        
        @self.app.callback(
            [Output('stats-container', 'children'),
             Output('traffic-volume-graph', 'figure'),
             Output('protocol-dist-graph', 'figure'),
             Output('http-analysis', 'children'),
             Output('incidents-table', 'children')],
            [Input('interval-component', 'n_intervals'),
             Input('tabs', 'value')]
        )
        def update_metrics(n, tab):
            traffic_data = self.traffic_analyzer.analyze_traffic()
            incidents = self.incident_detector.detect_incidents(traffic_data)
            
            if not traffic_data:
                return html.Div("No data available"), {}, {}, html.Div("No HTTP data"), html.Div("No incidents")
            
            df = pd.DataFrame(traffic_data)
            
            # Stats
            stats = traffic_data[0]['stats']
            stats_div = html.Div([
                html.Div([
                    html.H4("Total Packets"),
                    html.P(stats['total_packets'])
                ], style={'textAlign': 'center', 'padding': '1rem'}),
                html.Div([
                    html.H4("Unique Sources"),
                    html.P(stats['unique_sources'])
                ], style={'textAlign': 'center', 'padding': '1rem'}),
                html.Div([
                    html.H4("Unique Destinations"),
                    html.P(stats['unique_destinations'])
                ], style={'textAlign': 'center', 'padding': '1rem'}),
                html.Div([
                    html.H4("Avg Packet Size"),
                    html.P(f"{stats['avg_packet_size']:.2f} bytes")
                ], style={'textAlign': 'center', 'padding': '1rem'})
            ], style={'display': 'grid', 'gridTemplateColumns': 'repeat(auto-fit, minmax(200px, 1fr))', 'gap': '1rem'})
            
            # Traffic Volume Graph
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            traffic_fig = px.line(df, x='timestamp', y='length',
                                title='Network Traffic Volume',
                                labels={'timestamp': 'Time', 'length': 'Packet Size (bytes)'})
            traffic_fig.update_layout(
                plot_bgcolor='white',
                paper_bgcolor='white'
            )
            
            # Protocol Distribution
            protocol_fig = px.pie(df, names='protocol',
                                title='Protocol Distribution',
                                hole=0.3)
            protocol_fig.update_layout(
                plot_bgcolor='white',
                paper_bgcolor='white'
            )
            
            # HTTP Analysis
            http_data = df[df['protocol'].isin(['HTTP', 'HTTPS'])]
            if len(http_data) > 0:
                http_analysis = html.Div([
                    html.H4("HTTP/HTTPS Traffic"),
                    html.P(f"Total HTTP(S) Packets: {len(http_data)}"),
                    html.P(f"Average Size: {http_data['length'].mean():.2f} bytes"),
                    dcc.Graph(figure=px.bar(
                        http_data.groupby('dst_port')['length'].count(),
                        title='HTTP(S) Traffic by Port'
                    ))
                ])
            else:
                http_analysis = html.P("No HTTP/HTTPS traffic detected")
            
            # Incidents Table
            if incidents:
                incidents_div = html.Table([
                    html.Thead(html.Tr([
                        html.Th(col, style={'padding': '0.5rem', 'backgroundColor': '#f8f9fa'})
                        for col in ['Time', 'Severity', 'Type', 'Details']
                    ])),
                    html.Tbody([
                        html.Tr([
                            html.Td(incident['timestamp'], style={'padding': '0.5rem'}),
                            html.Td(html.Span(incident['severity'],
                                            style={'color': 'white',
                                                  'backgroundColor': {'HIGH': '#dc3545',
                                                                    'MEDIUM': '#ffc107',
                                                                    'LOW': '#28a745'}[incident['severity']],
                                                  'padding': '0.25rem 0.5rem',
                                                  'borderRadius': '4px'})),
                            html.Td(incident['type'], style={'padding': '0.5rem'}),
                            html.Td(incident['details'], style={'padding': '0.5rem'})
                        ]) for incident in incidents
                    ])
                ], style={'width': '100%', 'borderCollapse': 'collapse'})
            else:
                incidents_div = html.P("No incidents detected", style={'color': '#28a745'})
            
            return stats_div, traffic_fig, protocol_fig, http_analysis, incidents_div
    
    def run(self, debug=True):
        # Get port from environment variable for cloud deployment
        port = int(os.getenv('PORT', 8050))
        self.app.run(debug=debug, host='0.0.0.0', port=port)
