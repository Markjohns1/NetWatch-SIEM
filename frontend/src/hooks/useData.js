import { useQuery } from '@tanstack/react-query';
import api from '../api/client';

export const useDevices = () => {
    return useQuery({
        queryKey: ['devices'],
        queryFn: async () => {
            const { data } = await api.get('/devices/');
            return data;
        },
        refetchInterval: 10000, // Refetch every 10 seconds
    });
};

export const useAlerts = () => {
    return useQuery({
        queryKey: ['alerts'],
        queryFn: async () => {
            const { data } = await api.get('/alerts/');
            return data;
        },
        refetchInterval: 5000, // Refetch every 5 seconds
    });
};

export const useStats = () => {
    return useQuery({
        queryKey: ['stats'],
        queryFn: async () => {
            const { data } = await api.get('/alerts/stats');
            return data;
        },
        refetchInterval: 5000,
    });
};
export const useScanStatus = () => {
    return useQuery({
        queryKey: ['scanStatus'],
        queryFn: async () => {
            const { data } = await api.get('/alerts/scan/status');
            return data;
        },
        refetchInterval: 2000,
    });
};

export const useEvents = () => {
    return useQuery({
        queryKey: ['events'],
        queryFn: async () => {
            const { data } = await api.get('/alerts/events');
            return data;
        },
        refetchInterval: 3000,
    });
};
